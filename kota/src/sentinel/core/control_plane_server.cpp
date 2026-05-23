#include "control_plane_server.h"

#include <cstdlib>
#include <filesystem>
#include <iostream>

#include <grpcpp/grpcpp.h>

#include "../policy/kota_profile.h"
#include "../../../../api/gen/cpp/kota_control_plane.grpc.pb.h"

namespace kota {

namespace {

constexpr const char *kDefaultControlSocket = "/run/kota/kotad.sock";

class KotaControlPlaneService final : public kota::control::v1::KotaControlPlane::Service {
public:
    explicit KotaControlPlaneService(ControlPlaneCallbacks callbacks)
        : callbacks_(std::move(callbacks))
    {}

    grpc::Status ApplyPolicy(grpc::ServerContext * /*context*/,
                             const kota::control::v1::ApplyPolicyRequest *request,
                             kota::control::v1::ApplyPolicyResponse *response) override
    {
        if (request == nullptr || response == nullptr) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "invalid ApplyPolicy request");
        }
        const std::string policy_yaml = request->policy_yaml();
        if (policy_yaml.empty()) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "policy_yaml cannot be empty");
        }
        auto parsed = load_kota_profile_yaml_string(policy_yaml, "ApplyPolicyRequest");
        if (!parsed) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT, parsed.error());
        }
        if (!callbacks_.apply_policy) {
            return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                                "apply callback not configured");
        }
        auto policy_id = callbacks_.apply_policy(policy_yaml);
        if (!policy_id) {
            return grpc::Status(grpc::StatusCode::RESOURCE_EXHAUSTED, policy_id.error());
        }
        response->set_policy_id(*policy_id);
        response->set_created(true);
        response->set_message("policy accepted and reloaded");
        return grpc::Status::OK;
    }

    grpc::Status GetStatus(grpc::ServerContext * /*context*/,
                           const kota::control::v1::GetStatusRequest * /*request*/,
                           kota::control::v1::GetStatusResponse *response) override
    {
        if (response == nullptr) {
            return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                                "invalid GetStatus response");
        }
        if (!callbacks_.get_status_rows) {
            return grpc::Status(grpc::StatusCode::UNIMPLEMENTED,
                                "status callback not configured");
        }
        auto rows = callbacks_.get_status_rows();
        for (const auto &row : rows) {
            auto *w = response->add_workloads();
            w->set_workload_key(row.workload_key);
            w->set_namespace_(row.namespace_name);
            w->set_pod(row.pod_name);
            w->set_profile(row.profile);
            w->set_verdict(row.verdict);
            w->set_armed(row.armed);
        }
        return grpc::Status::OK;
    }

private:
    ControlPlaneCallbacks callbacks_;
};

} // namespace

std::expected<std::string, std::string>
control_socket_path_from_env()
{
    const char *e = std::getenv("KOTA_CONTROL_SOCK");
    const std::string out = (e && *e) ? std::string{e} : std::string{kDefaultControlSocket};
    if (out.empty() || out[0] != '/') {
        return std::unexpected("KOTA control socket must be an absolute path");
    }
    return out;
}

std::expected<std::unique_ptr<grpc::Server>, std::string>
start_control_plane_server(const std::string &socket_path,
                           ControlPlaneCallbacks callbacks)
{
    std::error_code ec;
    std::filesystem::create_directories(std::filesystem::path(socket_path).parent_path(), ec);
    if (ec) {
        return std::unexpected("control socket parent mkdir failed: " + ec.message());
    }
    std::filesystem::remove(socket_path, ec);
    static_cast<void>(ec);

    auto *service = new KotaControlPlaneService(std::move(callbacks));
    grpc::ServerBuilder builder;
    builder.AddListeningPort("unix://" + socket_path, grpc::InsecureServerCredentials());
    builder.RegisterService(service);
    auto server = builder.BuildAndStart();
    if (!server) {
        delete service;
        return std::unexpected("failed to start gRPC control server on unix://" +
                               socket_path);
    }
    std::cout << "[KOTA] control plane listening on unix://" << socket_path << '\n';
    return server;
}

void cleanup_control_socket_file(const std::string &socket_path)
{
    std::error_code ec;
    std::filesystem::remove(socket_path, ec);
}

} // namespace kota
