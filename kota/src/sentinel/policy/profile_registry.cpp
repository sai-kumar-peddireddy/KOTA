#include "profile_registry.h"
#include "kota_profile.h"

#include <bpf/bpf.h>
#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

namespace kota {

namespace {

std::filesystem::path profile_root_guess()
{
    if (const char *e = std::getenv("KOTA_PROFILE_DIR"); e && *e)
        return e;
    if (std::filesystem::exists("tests/fixtures/profiles"))
        return "tests/fixtures/profiles";
    if (std::filesystem::exists("deploy/profiles"))
        return "deploy/profiles";
    return "/etc/kota/profiles";
}

bool is_profile_dir_override_enabled()
{
    const char *e = std::getenv("KOTA_PROFILE_DIR");
    return e && *e;
}

struct StoredPolicyRecord {
    std::string id;
    std::string yaml;
};

std::filesystem::path default_policy_data_root()
{
    if (const char *e = std::getenv("KOTA_DATA_DIR"); e && *e)
        return e;
    if (const char *xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::filesystem::path(xdg) / "kota";
    return "/var/lib/kota";
}

std::filesystem::path sqlite_db_path_for(const std::filesystem::path &root)
{
    return root / "policy_store.sqlite3";
}

constexpr int SQLITE_OK = 0;
constexpr int SQLITE_ROW = 100;
constexpr int SQLITE_DONE = 101;
constexpr int SQLITE_OPEN_READWRITE = 0x00000002;
constexpr int SQLITE_OPEN_CREATE = 0x00000004;

struct sqlite3;
struct sqlite3_stmt;

struct SqliteApi {
    using open_v2_fn =
        int (*)(const char *, sqlite3 **, int, const char *);
    using close_fn = int (*)(sqlite3 *);
    using errstr_fn = const char *(*)(int);
    using exec_fn = int (*)(sqlite3 *, const char *,
                            int (*)(void *, int, char **, char **), void *,
                            char **);
    using free_fn = void (*)(void *);
    using prepare_v2_fn =
        int (*)(sqlite3 *, const char *, int, sqlite3_stmt **, const char **);
    using step_fn = int (*)(sqlite3_stmt *);
    using finalize_fn = int (*)(sqlite3_stmt *);
    using bind_text_fn = int (*)(sqlite3_stmt *, int, const char *, int,
                                 void (*)(void *));
    using column_text_fn = const unsigned char *(*)(sqlite3_stmt *, int);

    void *handle = nullptr;
    open_v2_fn open_v2 = nullptr;
    close_fn close = nullptr;
    errstr_fn errstr = nullptr;
    exec_fn exec = nullptr;
    free_fn free = nullptr;
    prepare_v2_fn prepare_v2 = nullptr;
    step_fn step = nullptr;
    finalize_fn finalize = nullptr;
    bind_text_fn bind_text = nullptr;
    column_text_fn column_text = nullptr;
};

std::expected<SqliteApi, std::string> load_sqlite_api()
{
    SqliteApi api{};
    for (const char *lib_name : {"libsqlite3.so.0", "libsqlite3.so"}) {
        api.handle = dlopen(lib_name, RTLD_NOW | RTLD_LOCAL);
        if (api.handle != nullptr)
            break;
    }
    if (api.handle == nullptr)
        return std::unexpected("ProfileRegistry: unable to load libsqlite3");

    auto load_symbol = [&](const char *name) -> void * { return dlsym(api.handle, name); };
    api.open_v2 = reinterpret_cast<SqliteApi::open_v2_fn>(load_symbol("sqlite3_open_v2"));
    api.close = reinterpret_cast<SqliteApi::close_fn>(load_symbol("sqlite3_close"));
    api.errstr = reinterpret_cast<SqliteApi::errstr_fn>(load_symbol("sqlite3_errstr"));
    api.exec = reinterpret_cast<SqliteApi::exec_fn>(load_symbol("sqlite3_exec"));
    api.free = reinterpret_cast<SqliteApi::free_fn>(load_symbol("sqlite3_free"));
    api.prepare_v2 =
        reinterpret_cast<SqliteApi::prepare_v2_fn>(load_symbol("sqlite3_prepare_v2"));
    api.step = reinterpret_cast<SqliteApi::step_fn>(load_symbol("sqlite3_step"));
    api.finalize = reinterpret_cast<SqliteApi::finalize_fn>(load_symbol("sqlite3_finalize"));
    api.bind_text =
        reinterpret_cast<SqliteApi::bind_text_fn>(load_symbol("sqlite3_bind_text"));
    api.column_text =
        reinterpret_cast<SqliteApi::column_text_fn>(load_symbol("sqlite3_column_text"));

    if (!api.open_v2 || !api.close || !api.errstr || !api.exec || !api.free ||
        !api.prepare_v2 || !api.step || !api.finalize || !api.bind_text ||
        !api.column_text) {
        dlclose(api.handle);
        return std::unexpected("ProfileRegistry: sqlite3 symbols missing");
    }
    return api;
}

std::string sqlite_error(const SqliteApi &api, int rc)
{
    const char *msg = api.errstr ? api.errstr(rc) : nullptr;
    if (msg && *msg)
        return msg;
    return "sqlite error " + std::to_string(rc);
}

std::expected<void, std::string> ensure_sqlite_schema(const SqliteApi &api, sqlite3 *db)
{
    constexpr const char *kSchema =
        "CREATE TABLE IF NOT EXISTS policies("
        "policy_id TEXT PRIMARY KEY,"
        "policy_yaml TEXT NOT NULL,"
        "updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())"
        ");";
    char *err_msg = nullptr;
    const int rc = api.exec(db, kSchema, nullptr, nullptr, &err_msg);
    if (rc == SQLITE_OK)
        return {};
    std::string msg = "ProfileRegistry: schema init failed: " + sqlite_error(api, rc);
    if (err_msg != nullptr) {
        msg += " (" + std::string(err_msg) + ")";
        api.free(err_msg);
    }
    return std::unexpected(msg);
}

class SqliteDbSession {
public:
    SqliteDbSession(const SqliteApi &api, const std::filesystem::path &db_path)
        : api_(api)
    {
        sqlite3 *db = nullptr;
        const int rc = api_.open_v2(
            db_path.c_str(), &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, nullptr);
        if (rc != SQLITE_OK || db == nullptr) {
            error_ = "ProfileRegistry: sqlite open failed for " + db_path.string() +
                     ": " + sqlite_error(api_, rc);
            return;
        }
        db_.reset(db);
    }
    bool ok() const { return db_ != nullptr; }
    const std::string &error() const { return error_; }
    sqlite3 *db() const { return db_.get(); }

private:
    struct DbCloser {
        const SqliteApi *api = nullptr;
        void operator()(sqlite3 *db) const
        {
            if (api && db)
                api->close(db);
        }
    };
    const SqliteApi &api_;
    std::unique_ptr<sqlite3, DbCloser> db_{nullptr, DbCloser{&api_}};
    std::string error_;
};

struct StmtCloser {
    const SqliteApi *api = nullptr;
    void operator()(sqlite3_stmt *stmt) const
    {
        if (api && stmt)
            api->finalize(stmt);
    }
};

std::expected<std::vector<StoredPolicyRecord>, std::string>
list_policies_from_sqlite(const std::filesystem::path &data_root)
{
    std::error_code ec;
    std::filesystem::create_directories(data_root, ec);
    if (ec)
        return std::unexpected("ProfileRegistry: cannot create " + data_root.string() +
                               ": " + ec.message());

    auto api_or = load_sqlite_api();
    if (!api_or)
        return std::unexpected(api_or.error());
    const auto &api = *api_or;

    SqliteDbSession session(api, sqlite_db_path_for(data_root));
    if (!session.ok())
        return std::unexpected(session.error());
    if (auto schema = ensure_sqlite_schema(api, session.db()); !schema)
        return std::unexpected(schema.error());

    constexpr const char *kQuery =
        "SELECT policy_id, policy_yaml FROM policies "
        "ORDER BY updated_at_unix ASC, policy_id ASC;";

    sqlite3_stmt *raw_stmt = nullptr;
    const int prep_rc = api.prepare_v2(session.db(), kQuery, -1, &raw_stmt, nullptr);
    if (prep_rc != SQLITE_OK || raw_stmt == nullptr) {
        return std::unexpected("ProfileRegistry: sqlite prepare(list) failed: " +
                               sqlite_error(api, prep_rc));
    }
    auto stmt = std::unique_ptr<sqlite3_stmt, StmtCloser>(raw_stmt, StmtCloser{&api});

    std::vector<StoredPolicyRecord> out;
    for (;;) {
        const int step_rc = api.step(stmt.get());
        if (step_rc == SQLITE_DONE)
            break;
        if (step_rc != SQLITE_ROW) {
            return std::unexpected("ProfileRegistry: sqlite step(list) failed: " +
                                   sqlite_error(api, step_rc));
        }
        const auto *id = api.column_text(stmt.get(), 0);
        const auto *yaml = api.column_text(stmt.get(), 1);
        if (id == nullptr || yaml == nullptr)
            continue;
        out.push_back(StoredPolicyRecord{
            .id = reinterpret_cast<const char *>(id),
            .yaml = reinterpret_cast<const char *>(yaml),
        });
    }
    return out;
}

std::expected<void, std::string> upsert_policy_to_sqlite(
    const std::filesystem::path &data_root, const std::string &policy_id,
    const std::string &policy_yaml)
{
    if (policy_id.empty() || policy_yaml.empty())
        return std::unexpected("ProfileRegistry: empty policy id/yaml");

    std::error_code ec;
    std::filesystem::create_directories(data_root, ec);
    if (ec)
        return std::unexpected("ProfileRegistry: cannot create " + data_root.string() +
                               ": " + ec.message());

    auto api_or = load_sqlite_api();
    if (!api_or)
        return std::unexpected(api_or.error());
    const auto &api = *api_or;

    SqliteDbSession session(api, sqlite_db_path_for(data_root));
    if (!session.ok())
        return std::unexpected(session.error());
    if (auto schema = ensure_sqlite_schema(api, session.db()); !schema)
        return std::unexpected(schema.error());

    constexpr const char *kUpsert =
        "INSERT INTO policies(policy_id, policy_yaml, updated_at_unix)"
        "VALUES(?, ?, unixepoch()) "
        "ON CONFLICT(policy_id) DO UPDATE SET "
        "policy_yaml=excluded.policy_yaml, updated_at_unix=excluded.updated_at_unix;";

    sqlite3_stmt *raw_stmt = nullptr;
    const int prep_rc = api.prepare_v2(session.db(), kUpsert, -1, &raw_stmt, nullptr);
    if (prep_rc != SQLITE_OK || raw_stmt == nullptr) {
        return std::unexpected("ProfileRegistry: sqlite prepare(upsert) failed: " +
                               sqlite_error(api, prep_rc));
    }
    auto stmt = std::unique_ptr<sqlite3_stmt, StmtCloser>(raw_stmt, StmtCloser{&api});

    if (const int bind_id = api.bind_text(stmt.get(), 1, policy_id.c_str(), -1, nullptr);
        bind_id != SQLITE_OK) {
        return std::unexpected("ProfileRegistry: sqlite bind(policy_id) failed: " +
                               sqlite_error(api, bind_id));
    }
    if (const int bind_yaml =
            api.bind_text(stmt.get(), 2, policy_yaml.c_str(), -1, nullptr);
        bind_yaml != SQLITE_OK) {
        return std::unexpected("ProfileRegistry: sqlite bind(policy_yaml) failed: " +
                               sqlite_error(api, bind_yaml));
    }
    if (const int step_rc = api.step(stmt.get()); step_rc != SQLITE_DONE) {
        return std::unexpected("ProfileRegistry: sqlite upsert failed: " +
                               sqlite_error(api, step_rc));
    }
    return {};
}

bool profile_registry_verbose_invalid_logs()
{
    const char *e = std::getenv("KOTA_LOG_INVALID_PROFILES");
    return e && (e[0] == '1' || e[0] == 't' || e[0] == 'T' || e[0] == 'y' || e[0] == 'Y');
}

std::expected<void, std::string> upsert_policy_ports(
    int map_fd, uint32_t profile_id, const KotaProfile &profile)
{
    if (map_fd < 0)
        return {};

    auto write_one = [&](std::uint16_t port, std::uint8_t klass)
        -> std::expected<void, std::string> {
        kota_policy_port_key key{};
        key.profile_id = profile_id;
        key.port = port;
        kota_policy_port_value value{};
        value.port_class = klass;
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
            return std::unexpected("kota_policy_ports update failed for profile_id=" +
                                   std::to_string(profile_id) + " port=" +
                                   std::to_string(port));
        }
        return {};
    };

    for (const auto port : profile.management_ports) {
        if (auto r = write_one(port, KOTA_PORT_CLASS_MGMT); !r)
            return r;
    }
    for (const auto port : profile.ai_data_ports) {
        if (auto r = write_one(port, KOTA_PORT_CLASS_AI); !r)
            return r;
    }
    return {};
}

std::expected<void, std::string> upsert_policy_ioctl(
    int map_fd, uint32_t profile_id, const KotaProfile &profile)
{
    if (map_fd < 0)
        return {};
    for (const auto cmd : profile.blocked_ioctl_cmds) {
        kota_policy_ioctl_key key{};
        key.profile_id = profile_id;
        key.ioctl_cmd = cmd;
        kota_policy_ioctl_value value{};
        value.action = KOTA_IOCTL_ACTION_DENY;
        if (bpf_map_update_elem(map_fd, &key, &value, BPF_ANY) != 0) {
            return std::unexpected("kota_policy_ioctl update failed for profile_id=" +
                                   std::to_string(profile_id) + " cmd=" +
                                   std::to_string(cmd));
        }
    }
    return {};
}

} // namespace

ProfileRegistry::ProfileRegistry(int profile_map_fd, int policy_ports_map_fd,
                                 int policy_ioctl_map_fd)
    : profile_map_fd_(profile_map_fd)
    , policy_ports_map_fd_(policy_ports_map_fd)
    , policy_ioctl_map_fd_(policy_ioctl_map_fd)
{}

std::expected<void, std::string> ProfileRegistry::load_defaults()
{
    static_cast<void>(profile_map_fd_);
    name_to_id_.clear();
    const bool verbose_invalid = profile_registry_verbose_invalid_logs();
    std::size_t invalid_count = 0;

    const auto root = profile_root_guess();
    const bool prefer_profile_dir_override = is_profile_dir_override_enabled();
    const auto sqlite_root = default_policy_data_root();

    uint32_t next_id = 1;
    auto register_profile = [&](const KotaProfile &profile)
        -> std::expected<void, std::string> {
        if (profile.name.empty() || name_to_id_.contains(profile.name))
            return {};
        const uint32_t id = next_id++;
        name_to_id_[profile.name] = id;
        if (auto ports = upsert_policy_ports(policy_ports_map_fd_, id, profile); !ports)
            return std::unexpected("ProfileRegistry: " + ports.error());
        if (auto ioctls = upsert_policy_ioctl(policy_ioctl_map_fd_, id, profile); !ioctls)
            return std::unexpected("ProfileRegistry: " + ioctls.error());
        return {};
    };

    if (!prefer_profile_dir_override) {
        if (auto stored = list_policies_from_sqlite(sqlite_root); stored && !stored->empty()) {
            for (const auto &entry : *stored) {
                auto profile =
                    load_kota_profile_yaml_string(entry.yaml, "sqlite:" + entry.id);
                if (!profile) {
                    invalid_count++;
                    if (verbose_invalid) {
                        std::cerr
                            << "[KOTA] ProfileRegistry: skip invalid stored policy "
                            << entry.id << ": " << profile.error() << '\n';
                    }
                    continue;
                }
                if (auto r = register_profile(*profile); !r)
                    return std::unexpected(r.error());
            }
            std::cout << "[KOTA] ProfileRegistry: loaded " << name_to_id_.size()
                      << " profiles from SQLite " << sqlite_db_path_for(sqlite_root)
                      << '\n';
        }
    }

    if (name_to_id_.empty() && std::filesystem::exists(root)) {
        for (const auto &entry : std::filesystem::directory_iterator(root)) {
            if (!entry.is_regular_file() || entry.path().extension() != ".yaml")
                continue;

            auto profile = load_kota_profile_yaml(entry.path());
            if (!profile) {
                invalid_count++;
                if (verbose_invalid) {
                    std::cerr << "[KOTA] ProfileRegistry: skip invalid profile "
                              << entry.path() << ": " << profile.error() << '\n';
                }
                continue;
            }
            if (auto r = register_profile(*profile); !r)
                return std::unexpected(r.error());

            if (!prefer_profile_dir_override) {
                std::ifstream in(entry.path());
                if (in) {
                    std::ostringstream yaml;
                    yaml << in.rdbuf();
                    auto persist =
                        upsert_policy_to_sqlite(sqlite_root, profile->name, yaml.str());
                    if (!persist) {
                        std::cerr << "[KOTA] ProfileRegistry: warn: persist profile "
                                  << profile->name << " failed: " << persist.error()
                                  << '\n';
                    }
                }
            }
        }
    }

    if (name_to_id_.empty()) {
        // Minimal fallback for empty/offline profile roots.
        name_to_id_["NVML-Lab-Fault-Injection"] = 1;
    }

    std::cout << "[KOTA] ProfileRegistry: loaded " << name_to_id_.size()
              << " profiles from " << root << '\n';
    if (prefer_profile_dir_override) {
        std::cout << "[KOTA] ProfileRegistry: KOTA_PROFILE_DIR is set; "
                     "skipping SQLite store at "
                  << sqlite_db_path_for(sqlite_root) << '\n';
    }
    if (invalid_count && !verbose_invalid) {
        std::cout << "[KOTA] ProfileRegistry: skipped " << invalid_count
                  << " invalid profile file(s) (set KOTA_LOG_INVALID_PROFILES=1 for details)\n";
    }
    return {};
}

std::expected<uint32_t, std::string>
ProfileRegistry::get_profile_id(std::string_view name) const
{
    auto it = name_to_id_.find(std::string{name});
    if (it == name_to_id_.end())
        return std::unexpected{"Profile not found: " + std::string{name}};
    return it->second;
}

} // namespace kota
