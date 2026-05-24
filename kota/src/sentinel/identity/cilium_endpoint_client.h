#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>

namespace kota {

struct CiliumEndpointFields {
    std::string pod_ip;
    std::string host_veth_ifname;
    std::string pod_name;
    std::string namespace_name;
    uint32_t    identity_id   = 0;
    std::string profile_label; /* value after "k8s:kota.ai/profile=" */
};

/**
 * Resolve endpoint metadata for a 64-hex CRI container ID via the Cilium agent
 * Unix socket.
 *
 * Primary: `GET /v1/endpoint/container-id:{cid}` (single JSON object; agent
 * resolves by prefix per OpenAPI). On 404, returns nullopt. On 400/405 or
 * non-object 200, falls back to `GET /v1/endpoint` list + scan (TTL cache).
 *
 * - unexpected: I/O, HTTP, or JSON failure (callers may log and fall back).
 * - nullopt: no matching endpoint (callers should use legacy OCI / proc path).
 *
 * @param bypass_cache When true, ignore the in-memory TTL cache and refetch
 *        the full `/v1/endpoint` list on fallback (use after a short sleep so
 *        Cilium can publish a new row).
 */
std::expected<std::optional<CiliumEndpointFields>, std::string>
cilium_find_endpoint_by_container_id(const std::string &socket_path,
                                     const std::string &container_id_64,
                                     bool bypass_cache = false);

} // namespace kota
