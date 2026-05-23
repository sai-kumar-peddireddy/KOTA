#pragma once

#include <expected>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace grpc {
class Server;
}

namespace kota {

struct ControlStatusRow {
    std::string workload_key;
    std::string namespace_name;
    std::string pod_name;
    std::string profile;
    std::string verdict;
    bool        armed = false;
};

struct ControlPlaneCallbacks {
    std::function<std::expected<std::string, std::string>(const std::string &policy_yaml)>
        apply_policy;
    std::function<std::vector<ControlStatusRow>()> get_status_rows;
};

std::expected<std::string, std::string>
control_socket_path_from_env();

std::expected<std::unique_ptr<grpc::Server>, std::string>
start_control_plane_server(const std::string &socket_path,
                           ControlPlaneCallbacks callbacks);

void cleanup_control_socket_file(const std::string &socket_path);

} // namespace kota
