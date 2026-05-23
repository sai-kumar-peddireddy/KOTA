#include "profile_store.h"

#include <cstdlib>
#include <dlfcn.h>
#include <filesystem>
#include <memory>
#include <string_view>
#include <utility>

namespace kota {
namespace {

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
    using column_int64_fn = long long (*)(sqlite3_stmt *, int);

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
    column_int64_fn column_int64 = nullptr;
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
        return std::unexpected("ProfileStore: unable to dlopen libsqlite3");

    auto load_symbol = [&](const char *name) -> void * {
        void *sym = dlsym(api.handle, name);
        return sym;
    };

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
    api.column_int64 =
        reinterpret_cast<SqliteApi::column_int64_fn>(load_symbol("sqlite3_column_int64"));

    if (!api.open_v2 || !api.close || !api.errstr || !api.exec || !api.free ||
        !api.prepare_v2 || !api.step || !api.finalize || !api.bind_text ||
        !api.column_text || !api.column_int64) {
        dlclose(api.handle);
        return std::unexpected(
            "ProfileStore: sqlite3 symbols missing in libsqlite3");
    }
    return api;
}

std::string sqlite_error(const SqliteApi &api, int rc)
{
    const char *msg = api.errstr ? api.errstr(rc) : nullptr;
    if (msg && *msg)
        return msg;
    return "sqlite error code " + std::to_string(rc);
}

class SqliteSession {
public:
    SqliteSession(const SqliteApi &api, const std::filesystem::path &db_path, int flags)
        : api_(api)
    {
        sqlite3 *db = nullptr;
        const int rc = api_.open_v2(db_path.c_str(), &db, flags, nullptr);
        if (rc != SQLITE_OK || db == nullptr) {
            open_error_ =
                "ProfileStore: open " + db_path.string() + ": " + sqlite_error(api_, rc);
            return;
        }
        db_.reset(db);
    }

    bool ok() const { return db_ != nullptr; }
    const std::string &error() const { return open_error_; }
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
    std::string open_error_;
};

struct StmtCloser {
    const SqliteApi *api = nullptr;
    void operator()(sqlite3_stmt *stmt) const
    {
        if (api && stmt)
            api->finalize(stmt);
    }
};

std::expected<void, std::string> ensure_schema(const SqliteApi &api, sqlite3 *db)
{
    constexpr const char *kSchemaSql =
        "CREATE TABLE IF NOT EXISTS policies("
        "policy_id TEXT PRIMARY KEY,"
        "policy_yaml TEXT NOT NULL,"
        "updated_at_unix INTEGER NOT NULL DEFAULT (unixepoch())"
        ");";

    char *err_msg = nullptr;
    const int rc = api.exec(db, kSchemaSql, nullptr, nullptr, &err_msg);
    if (rc != SQLITE_OK) {
        std::string msg = "ProfileStore: schema init failed: " + sqlite_error(api, rc);
        if (err_msg != nullptr) {
            msg += " (" + std::string(err_msg) + ")";
            api.free(err_msg);
        }
        return std::unexpected(msg);
    }
    return {};
}

} // namespace

ProfileStore::ProfileStore(std::filesystem::path root_dir)
    : root_dir_{std::move(root_dir)}
{}

std::filesystem::path ProfileStore::default_data_root()
{
    if (const char *e = std::getenv("KOTA_DATA_DIR"); e && *e)
        return e;
    if (const char *xdg = std::getenv("XDG_DATA_HOME"); xdg && *xdg)
        return std::filesystem::path(xdg) / "kota";
    return "/var/lib/kota";
}

std::expected<std::filesystem::path, std::string>
ProfileStore::yaml_path_for(uint32_t profile_id) const
{
    if (profile_id == 0U)
        return std::unexpected{
            "unmanaged: profile_id=0 (no OCI kota.ai/profile / no registered "
            "profile per kota_common.h)"};

    if (root_dir_.empty())
        return std::unexpected("ProfileStore: empty root");

    return root_dir_ / (std::to_string(static_cast<unsigned long long>(profile_id)) +
                        ".yaml");
}

std::filesystem::path ProfileStore::sqlite_db_path() const
{
    return root_dir_ / "policy_store.sqlite3";
}

std::expected<void, std::string>
ProfileStore::upsert_policy_yaml(std::string policy_id, std::string policy_yaml) const
{
    if (root_dir_.empty())
        return std::unexpected("ProfileStore: empty root");
    if (policy_id.empty())
        return std::unexpected("ProfileStore: empty policy id");
    if (policy_yaml.empty())
        return std::unexpected("ProfileStore: empty policy yaml");

    std::error_code ec;
    std::filesystem::create_directories(root_dir_, ec);
    if (ec)
        return std::unexpected("ProfileStore: mkdir failed for " + root_dir_.string() +
                               ": " + ec.message());

    auto api_or = load_sqlite_api();
    if (!api_or)
        return std::unexpected(api_or.error());
    const auto &api = *api_or;

    SqliteSession session(api, sqlite_db_path(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    if (!session.ok())
        return std::unexpected(session.error());
    if (auto schema = ensure_schema(api, session.db()); !schema)
        return std::unexpected(schema.error());

    constexpr const char *kSql =
        "INSERT INTO policies(policy_id, policy_yaml, updated_at_unix)"
        "VALUES(?, ?, unixepoch()) "
        "ON CONFLICT(policy_id) DO UPDATE SET "
        "policy_yaml=excluded.policy_yaml, updated_at_unix=excluded.updated_at_unix;";

    sqlite3_stmt *stmt = nullptr;
    const int prep_rc = api.prepare_v2(session.db(), kSql, -1, &stmt, nullptr);
    if (prep_rc != SQLITE_OK || stmt == nullptr)
        return std::unexpected("ProfileStore: prepare upsert failed: " +
                               sqlite_error(api, prep_rc));

    auto finalize_guard = std::unique_ptr<sqlite3_stmt, StmtCloser>(
        stmt, StmtCloser{&api});

    if (const int bind_id = api.bind_text(stmt, 1, policy_id.c_str(), -1, nullptr);
        bind_id != SQLITE_OK) {
        return std::unexpected("ProfileStore: bind policy id failed: " +
                               sqlite_error(api, bind_id));
    }
    if (const int bind_yaml = api.bind_text(stmt, 2, policy_yaml.c_str(), -1, nullptr);
        bind_yaml != SQLITE_OK) {
        return std::unexpected("ProfileStore: bind policy yaml failed: " +
                               sqlite_error(api, bind_yaml));
    }
    if (const int step_rc = api.step(stmt); step_rc != SQLITE_DONE)
        return std::unexpected("ProfileStore: upsert failed: " + sqlite_error(api, step_rc));
    return {};
}

std::expected<std::vector<StoredPolicyRecord>, std::string>
ProfileStore::list_policies() const
{
    if (root_dir_.empty())
        return std::unexpected("ProfileStore: empty root");

    std::error_code ec;
    std::filesystem::create_directories(root_dir_, ec);
    if (ec)
        return std::unexpected("ProfileStore: mkdir failed for " + root_dir_.string() +
                               ": " + ec.message());

    auto api_or = load_sqlite_api();
    if (!api_or)
        return std::unexpected(api_or.error());
    const auto &api = *api_or;

    SqliteSession session(api, sqlite_db_path(), SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    if (!session.ok())
        return std::unexpected(session.error());
    if (auto schema = ensure_schema(api, session.db()); !schema)
        return std::unexpected(schema.error());

    constexpr const char *kSql =
        "SELECT policy_id, policy_yaml, updated_at_unix "
        "FROM policies ORDER BY updated_at_unix ASC, policy_id ASC;";

    sqlite3_stmt *stmt = nullptr;
    const int prep_rc = api.prepare_v2(session.db(), kSql, -1, &stmt, nullptr);
    if (prep_rc != SQLITE_OK || stmt == nullptr)
        return std::unexpected("ProfileStore: prepare list failed: " +
                               sqlite_error(api, prep_rc));
    auto finalize_guard = std::unique_ptr<sqlite3_stmt, StmtCloser>(
        stmt, StmtCloser{&api});

    std::vector<StoredPolicyRecord> out;
    for (;;) {
        const int step_rc = api.step(stmt);
        if (step_rc == SQLITE_DONE)
            break;
        if (step_rc != SQLITE_ROW)
            return std::unexpected("ProfileStore: list step failed: " +
                                   sqlite_error(api, step_rc));

        const auto *id_text = api.column_text(stmt, 0);
        const auto *yaml_text = api.column_text(stmt, 1);
        if (id_text == nullptr || yaml_text == nullptr)
            continue;
        StoredPolicyRecord rec{};
        rec.id = reinterpret_cast<const char *>(id_text);
        rec.yaml = reinterpret_cast<const char *>(yaml_text);
        rec.updated_at_unix = static_cast<std::int64_t>(api.column_int64(stmt, 2));
        out.push_back(std::move(rec));
    }
    return out;
}

} // namespace kota
