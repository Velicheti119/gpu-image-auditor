#include "checks.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/utsname.h>
#include <vector>
#include <algorithm>

namespace {

// ------------------------------------------------------------
// General helpers
// ------------------------------------------------------------

std::string execCommand(const std::string& command)
{
    std::string result;

    FILE* pipe = popen(command.c_str(), "r");

    if (!pipe) {
        return "";
    }

    char buffer[256];

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }

    pclose(pipe);

    return result;
}

std::string trim(const std::string& input)
{
    const char* whitespace = " \t\n\r";

    const size_t start = input.find_first_not_of(whitespace);

    if (start == std::string::npos) {
        return "";
    }

    const size_t end = input.find_last_not_of(whitespace);

    return input.substr(start, end - start + 1);
}

bool contains(
    const std::string& text,
    const std::string& value)
{
    return text.find(value) != std::string::npos;
}

// ------------------------------------------------------------
// Network parsing helpers
// ------------------------------------------------------------

std::string removeScopeId(std::string address)
{
    const size_t percent = address.find('%');

    if (percent != std::string::npos) {
        address = address.substr(0, percent);
    }

    return address;
}

bool isLoopbackAddress(const std::string& address)
{
    std::string normalized = removeScopeId(address);

    if (normalized == "127.0.0.1") {
        return true;
    }

    if (normalized.rfind("127.", 0) == 0) {
        return true;
    }

    if (normalized == "::1") {
        return true;
    }

    return false;
}

bool isWildcardAddress(const std::string& address)
{
    std::string normalized = removeScopeId(address);

    return normalized == "0.0.0.0" ||
           normalized == "::";
}

bool parseEndpoint(
    const std::string& endpoint,
    std::string& address,
    int& port)
{
    std::string value = endpoint;

    value = trim(value);

    // [IPv6]:port
    if (!value.empty() && value.front() == '[') {

        const size_t closeBracket = value.find(']');

        if (closeBracket == std::string::npos) {
            return false;
        }

        address = value.substr(
            1,
            closeBracket - 1
        );

        const size_t colon = value.find(
            ':',
            closeBracket
        );

        if (colon == std::string::npos) {
            return false;
        }

        try {
            port = std::stoi(
                value.substr(colon + 1)
            );
        }
        catch (...) {
            return false;
        }

        return true;
    }

    // IPv4:port
    const size_t lastColon = value.rfind(':');

    if (lastColon == std::string::npos) {
        return false;
    }

    address = value.substr(0, lastColon);

    std::string portString =
        value.substr(lastColon + 1);

    // Handle ss output such as :::111
    if (address == "::") {
        // Already normalized.
    }

    try {
        port = std::stoi(portString);
    }
    catch (...) {
        return false;
    }

    return true;
}

bool isExternalListener(const std::string& address)
{
    if (isLoopbackAddress(address)) {
        return false;
    }

    return true;
}

std::string extractProcessName(
    const std::string& line)
{
    const size_t usersPos =
        line.find("users:((");

    if (usersPos == std::string::npos) {
        return "";
    }

    const size_t start =
        usersPos + std::strlen("users:((\"");

    const size_t end =
        line.find(
            '"',
            start
        );

    if (end == std::string::npos) {
        return "";
    }

    return line.substr(
        start,
        end - start
    );
}

// ------------------------------------------------------------
// System information
// ------------------------------------------------------------

std::string readOSName()
{
    std::ifstream file("/etc/os-release");

    if (!file) {
        return "Unknown";
    }

    std::string line;

    while (std::getline(file, line)) {

        if (line.rfind("PRETTY_NAME=", 0) == 0) {

            std::string value =
                line.substr(
                    std::strlen("PRETTY_NAME=")
                );

            if (!value.empty() &&
                value.front() == '"' &&
                value.back() == '"') {

                value = value.substr(
                    1,
                    value.size() - 2
                );
            }

            return value;
        }
    }

    return "Unknown";
}

} // namespace


// ============================================================
// SYSTEM INFORMATION
// ============================================================

SystemInfo collectSystemInfo()
{
    SystemInfo info;

    struct utsname kernelInfo {};

    if (uname(&kernelInfo) == 0) {
        info.kernel = kernelInfo.release;
    }
    else {
        info.kernel = "Unknown";
    }

    info.os = readOSName();

    std::string gpuInfo =
        execCommand(
            "nvidia-smi "
            "--query-gpu=name,driver_version "
            "--format=csv,noheader 2>/dev/null"
        );

    gpuInfo = trim(gpuInfo);

    if (!gpuInfo.empty()) {

        const size_t comma =
            gpuInfo.find(',');

        if (comma != std::string::npos) {

            info.gpu =
                trim(
                    gpuInfo.substr(
                        0,
                        comma
                    )
                );

            info.driver =
                trim(
                    gpuInfo.substr(
                        comma + 1
                    )
                );
        }
        else {
            info.gpu = gpuInfo;
        }
    }
    else {
        info.gpu = "Unavailable";
        info.driver = "Unavailable";
    }

    std::string cudaInfo =
        execCommand(
            "nvidia-smi 2>/dev/null | "
            "grep 'CUDA Version'"
        );

    cudaInfo = trim(cudaInfo);

    if (!cudaInfo.empty()) {

        const size_t pos =
            cudaInfo.find("CUDA Version:");

        if (pos != std::string::npos) {

            info.cuda =
                trim(
                    cudaInfo.substr(
                        pos +
                        std::strlen("CUDA Version:")
                    )
                );
        }
    }

    if (info.cuda.empty()) {
        info.cuda = "Unavailable";
    }

    return info;
}


// ============================================================
// NETWORK LISTENERS
// ============================================================

std::vector<Listener> collectListeners()
{
    std::vector<Listener> listeners;

    const std::string output =
        execCommand(
            "sudo ss -lntup 2>/dev/null"
        );

    std::istringstream stream(output);

    std::string line;

    while (std::getline(stream, line)) {

        line = trim(line);

        if (line.empty()) {
            continue;
        }

        if (line.rfind("Netid", 0) == 0) {
            continue;
        }

        std::istringstream row(line);

        std::string protocol;
        std::string state;
        std::string recvQueue;
        std::string sendQueue;
        std::string localAddress;
        std::string peerAddress;

        row >> protocol;
        row >> state;
        row >> recvQueue;
        row >> sendQueue;
        row >> localAddress;
        row >> peerAddress;

        if (localAddress.empty()) {
            continue;
        }

        std::string address;
        int port = 0;

        if (!parseEndpoint(
                localAddress,
                address,
                port)) {

            continue;
        }

        Listener listener;

        listener.protocol = protocol;
        listener.address = address;
        listener.port = port;
        listener.process =
            extractProcessName(line);
        listener.externallyBound =
            isExternalListener(address);

        listeners.push_back(listener);
    }

    return listeners;
}


// ============================================================
// SSH ACTIVITY
// ============================================================

std::vector<SSHSession>
collectCurrentSSHSessions()
{
    std::vector<SSHSession> sessions;

    const std::string output =
        execCommand("who");

    std::istringstream stream(output);

    std::string line;

    while (std::getline(stream, line)) {

        std::istringstream row(line);

        SSHSession session;

        row >> session.user;
        row >> session.terminal;

        std::string date;
        std::string time;

        row >> date;
        row >> time;

        session.loginTime =
            date + " " + time;

        std::string remainder;

        std::getline(row, remainder);

        const size_t openParen =
            remainder.find('(');

        const size_t closeParen =
            remainder.find(')');

        if (openParen != std::string::npos &&
            closeParen != std::string::npos &&
            closeParen > openParen) {

            session.source =
                remainder.substr(
                    openParen + 1,
                    closeParen - openParen - 1
                );
        }
        else {
            session.source = "local";
        }

        if (!session.user.empty()) {
            sessions.push_back(session);
        }
    }

    return sessions;
}


std::vector<SSHLogin>
collectSSHLoginHistory(int limit)
{
    std::vector<SSHLogin> logins;

    std::string command =
        "last -i -n " +
        std::to_string(limit) +
        " 2>/dev/null";

    const std::string output =
        execCommand(command);

    std::istringstream stream(output);

    std::string line;

    while (std::getline(stream, line)) {

        line = trim(line);

        if (line.empty()) {
            continue;
        }

        if (line.find("wtmp begins") !=
            std::string::npos) {

            continue;
        }

        std::istringstream row(line);

        SSHLogin login;

        std::string terminal;

        row >> login.user;
        row >> terminal;
        row >> login.source;

        if (login.user.empty()) {
            continue;
        }

        std::string remainder;

        std::getline(row, remainder);

        remainder = trim(remainder);

        login.loginTime = remainder;

        logins.push_back(login);
    }

    return logins;
}


std::vector<SSHFailedAttempt>
collectSSHFailedAttempts(int limit)
{
    std::vector<SSHFailedAttempt> attempts;

    std::string command =
        "sudo lastb -i -n " +
        std::to_string(limit) +
        " 2>/dev/null";

    const std::string output =
        execCommand(command);

    std::istringstream stream(output);

    std::string line;

    while (std::getline(stream, line)) {

        line = trim(line);

        if (line.empty()) {
            continue;
        }

        if (line.find("btmp begins") !=
            std::string::npos) {

            continue;
        }

        std::istringstream row(line);

        SSHFailedAttempt attempt;

        std::string terminal;

        row >> attempt.user;
        row >> terminal;
        row >> attempt.source;

        if (attempt.user.empty()) {
            continue;
        }

        std::string remainder;

        std::getline(row, remainder);

        attempt.attemptTime =
            trim(remainder);

        attempts.push_back(attempt);
    }

    return attempts;
}


// ============================================================
// SECURITY CHECKS
// ============================================================

std::vector<Finding>
runChecks(const std::vector<Listener>& listeners)
{
    std::vector<Finding> findings;

    // --------------------------------------------------------
    // SSH-001
    // --------------------------------------------------------

    std::string rootLogin =
        trim(
            execCommand(
                "sudo sshd -T 2>/dev/null | "
                "grep '^permitrootlogin '"
            )
        );

    if (rootLogin ==
        "permitrootlogin no") {

        findings.push_back({
            "SSH-001",
            Severity::PASS,
            "SSH root login disabled",
            rootLogin,
            0
        });

    }
    else if (
        contains(
            rootLogin,
            "prohibit-password"
        ) ||
        contains(
            rootLogin,
            "without-password"
        )) {

        findings.push_back({
            "SSH-001",
            Severity::WARN,
            "SSH root login may be enabled",
            rootLogin,
            5
        });

    }
    else {

        findings.push_back({
            "SSH-001",
            Severity::HIGH,
            "SSH root login may be enabled",
            rootLogin,
            15
        });
    }


    // --------------------------------------------------------
    // SSH-002
    // --------------------------------------------------------

    std::string passwordAuth =
        trim(
            execCommand(
                "sudo sshd -T 2>/dev/null | "
                "grep '^passwordauthentication '"
            )
        );

    if (passwordAuth ==
        "passwordauthentication no") {

        findings.push_back({
            "SSH-002",
            Severity::PASS,
            "SSH password authentication disabled",
            passwordAuth,
            0
        });

    }
    else {

        findings.push_back({
            "SSH-002",
            Severity::WARN,
            "SSH password authentication enabled",
            passwordAuth,
            10
        });
    }


    // --------------------------------------------------------
    // NET-001
    // --------------------------------------------------------

    std::string ufw =
        trim(
            execCommand(
                "sudo ufw status 2>/dev/null"
            )
        );

    if (contains(ufw, "Status: active")) {

        findings.push_back({
            "NET-001",
            Severity::PASS,
            "Host firewall active",
            "UFW is active.",
            0
        });

    }
    else {

        findings.push_back({
            "NET-001",
            Severity::WARN,
            "Host firewall inactive",
            "UFW is inactive. Cloud/provider firewall may still provide protection.",
            5
        });
    }


    // --------------------------------------------------------
    // NET-002 RPCbind
    // --------------------------------------------------------

    bool rpcbindExternal = false;

    for (const Listener& listener : listeners) {

        if (!listener.externallyBound) {
            continue;
        }

        if (listener.port == 111 ||
            listener.process == "rpcbind") {

            rpcbindExternal = true;
            break;
        }
    }

    if (rpcbindExternal) {

        findings.push_back({
            "NET-002",
            Severity::HIGH,
            "RPCbind exposed on wildcard interface",
            "RPCbind is listening on a non-loopback interface.",
            20
        });
    }


    // --------------------------------------------------------
    // NET-003 Jupyter
    // --------------------------------------------------------

    bool jupyterExternal = false;

    for (const Listener& listener : listeners) {

        if (!listener.externallyBound) {
            continue;
        }

        if (contains(
                listener.process,
                "jupyter")) {

            jupyterExternal = true;
            break;
        }
    }

    if (jupyterExternal) {

        findings.push_back({
            "NET-003",
            Severity::HIGH,
            "Jupyter externally exposed",
            "Jupyter is listening on a non-loopback interface.",
            20
        });

    }
    else {

        findings.push_back({
            "NET-003",
            Severity::PASS,
            "Jupyter restricted to localhost",
            "No externally bound Jupyter listener detected.",
            0
        });
    }


    // --------------------------------------------------------
    // NET-004 SSH exposure
    // --------------------------------------------------------

    bool sshExternal = false;

    for (const Listener& listener : listeners) {

        if (!listener.externallyBound) {
            continue;
        }

        if (listener.port == 22 ||
            listener.process == "sshd") {

            sshExternal = true;
            break;
        }
    }

    if (sshExternal) {

        findings.push_back({
            "NET-004",
            Severity::WARN,
            "SSH externally exposed",
            "SSH is listening on a non-loopback interface.",
            5
        });

    }
    else {

        findings.push_back({
            "NET-004",
            Severity::PASS,
            "SSH not externally bound",
            "No externally bound SSH listener detected.",
            0
        });
    }


    // --------------------------------------------------------
    // NET-005 unknown listeners
    // --------------------------------------------------------

    std::vector<std::string> unknownListeners;

    for (const Listener& listener : listeners) {

        if (!listener.externallyBound) {
            continue;
        }

        bool known =
            listener.port == 111 ||
            listener.port == 22 ||
            listener.process == "rpcbind" ||
            contains(listener.process, "jupyter") ||
            listener.port == 53 ||
            listener.port == 323;

        if (!known) {

            std::ostringstream item;

            item << listener.protocol
                 << " "
                 << listener.address
                 << ":"
                 << listener.port;

            if (!listener.process.empty()) {
                item << " (" << listener.process << ")";
            }

            unknownListeners.push_back(
                item.str()
            );
        }
    }

    if (!unknownListeners.empty()) {

        std::ostringstream details;

        details << "Externally bound listeners: ";

        for (size_t i = 0;
             i < unknownListeners.size();
             ++i) {

            if (i > 0) {
                details << ", ";
            }

            details << unknownListeners[i];
        }

        findings.push_back({
            "NET-005",
            Severity::WARN,
            "Unknown external listeners detected",
            details.str(),
            5
        });
    }


    // --------------------------------------------------------
    // NET-006
    // --------------------------------------------------------

    bool externalFound = false;

    for (const Listener& listener : listeners) {

        if (listener.externallyBound) {

            // Ignore common infrastructure listeners.
            if (listener.port == 53 ||
                listener.port == 323) {

                continue;
            }

            externalFound = true;
            break;
        }
    }

    if (!externalFound) {

        findings.push_back({
            "NET-006",
            Severity::PASS,
            "No external listeners detected",
            "No non-loopback listeners were detected.",
            0
        });
    }


    // --------------------------------------------------------
    // GPU-001
    // --------------------------------------------------------

    std::string nvidia =
        execCommand(
            "nvidia-smi >/dev/null 2>&1; "
            "echo $?"
        );

    if (trim(nvidia) == "0") {

        findings.push_back({
            "GPU-001",
            Severity::PASS,
            "NVIDIA GPU detected",
            "nvidia-smi is operational.",
            0
        });

    }
    else {

        findings.push_back({
            "GPU-001",
            Severity::INFO,
            "NVIDIA GPU unavailable",
            "nvidia-smi could not access the GPU.",
            0
        });
    }


    // --------------------------------------------------------
    // GPU-002
    // --------------------------------------------------------

    std::string devicePermissions =
        execCommand(
            "stat -c '%a %U:%G %n' "
            "/dev/nvidia* 2>/dev/null"
        );

    if (contains(
            devicePermissions,
            "666 root:root")) {

        findings.push_back({
            "GPU-002",
            Severity::WARN,
            "NVIDIA device node is world-accessible",
            "One or more NVIDIA device nodes allow read/write access to everyone.",
            8
        });

    }
    else if (
        devicePermissions.empty()) {

        findings.push_back({
            "GPU-002",
            Severity::INFO,
            "NVIDIA device permissions unavailable",
            "No NVIDIA device nodes were found.",
            0
        });

    }
    else {

        findings.push_back({
            "GPU-002",
            Severity::PASS,
            "NVIDIA device permissions restricted",
            "NVIDIA device nodes are not world-writable.",
            0
        });
    }


    // --------------------------------------------------------
    // SVC-001 Docker
    // --------------------------------------------------------

    std::string docker =
        execCommand(
            "docker info 2>&1"
        );

    if (contains(
            docker,
            "permission denied")) {

        findings.push_back({
            "SVC-001",
            Severity::INFO,
            "Docker installed but not accessible",
            "Current user cannot access the Docker API.",
            0
        });

    }
    else if (
        contains(
            docker,
            "Server Version")) {

        findings.push_back({
            "SVC-001",
            Severity::INFO,
            "Docker accessible",
            "Docker daemon is accessible to the current user.",
            0
        });

    }
    else {

        findings.push_back({
            "SVC-001",
            Severity::INFO,
            "Docker unavailable",
            "Docker does not appear to be accessible.",
            0
        });
    }

    return findings;
}


// ============================================================
// SEVERITY
// ============================================================

std::string severityToString(
    Severity severity)
{
    switch (severity) {

        case Severity::PASS:
            return "PASS";

        case Severity::INFO:
            return "INFO";

        case Severity::WARN:
            return "WARN";

        case Severity::HIGH:
            return "HIGH";
    }

    return "UNKNOWN";
}


// ============================================================
// SCORE
// ============================================================

int calculateScore(
    const std::vector<Finding>& findings)
{
    int score = 100;

    for (const Finding& finding : findings) {
        score -= finding.points;
    }

    if (score < 0) {
        score = 0;
    }

    return score;
}


// ============================================================
// REMEDIATION GENERATION
// ============================================================

std::vector<Remediation>
generateRemediations(
    const std::vector<Finding>& findings)
{
    std::vector<Remediation> remediations;

    for (const Finding& finding : findings) {

        if (finding.id == "SSH-001" &&
            finding.severity != Severity::PASS) {

            remediations.push_back({
                "REM-001",
                "SSH-001",
                "Disable SSH root login",
                "Set PermitRootLogin to 'no', validate the SSH configuration, reload sshd, and verify the effective policy.",
                Severity::HIGH,
                false,
                true
            });
        }

        else if (finding.id == "SSH-002" &&
                 finding.severity != Severity::PASS) {

            remediations.push_back({
                "REM-002",
                "SSH-002",
                "Disable SSH password authentication",
                "Set PasswordAuthentication to 'no', validate the SSH configuration, and reload sshd.",
                Severity::HIGH,
                false,
                true
            });
        }

        else if (finding.id == "NET-002" &&
                 finding.severity != Severity::PASS) {

            remediations.push_back({
                "REM-003",
                "NET-002",
                "Disable externally exposed rpcbind",
                "Stop and disable rpcbind/rpcbind.socket if RPC services are not required.",
                Severity::HIGH,
                false,
                true
            });
        }

        else if (finding.id == "NET-004" &&
                 finding.severity != Severity::PASS) {

            remediations.push_back({
                "REM-004",
                "NET-004",
                "Restrict SSH exposure",
                "Restrict SSH access using firewall policy while preserving the current administrative connection.",
                Severity::HIGH,
                false,
                true
            });
        }

        else if (finding.id == "NET-005" &&
                 finding.severity != Severity::PASS) {

            remediations.push_back({
                "REM-005",
                "NET-005",
                "Review unknown external listeners",
                "Identify the service and restrict or disable it if unnecessary.",
                Severity::WARN,
                false,
                true
            });
        }

        else if (finding.id == "GPU-002" &&
                 finding.severity != Severity::PASS) {

            remediations.push_back({
                "REM-006",
                "GPU-002",
                "Restrict NVIDIA device permissions",
                "Configure persistent NVIDIA device permissions using the appropriate device/udev mechanism.",
                Severity::HIGH,
                false,
                true
            });
        }
    }

    return remediations;
}


// ============================================================
// REMEDIATION PLAN
// ============================================================

void printRemediationPlan(
    const std::vector<Remediation>& remediations)
{
    std::cout
        << "\nREMEDIATION PLAN\n"
        << "========================================\n";

    if (remediations.empty()) {

        std::cout
            << "No remediation actions required.\n";

        return;
    }

    for (const Remediation& remediation :
         remediations) {

        std::cout
            << "\n["
            << remediation.id
            << "] "
            << remediation.title
            << "\n";

        std::cout
            << "Finding: "
            << remediation.findingId
            << "\n";

        std::cout
            << "Risk: "
            << severityToString(
                   remediation.risk)
            << "\n";

        std::cout
            << "Requires sudo: "
            << (remediation.requiresSudo
                ? "yes"
                : "no")
            << "\n";

        std::cout
            << "Requires reboot: "
            << (remediation.requiresReboot
                ? "yes"
                : "no")
            << "\n";

        std::cout
            << "Action:\n  "
            << remediation.description
            << "\n";
    }
}


// ============================================================
// REMEDIATION ENFORCEMENT
// ============================================================

RemediationResult enforceRemediation(
    const Remediation& remediation)
{
    // --------------------------------------------------------
    // REM-001
    // --------------------------------------------------------

    if (remediation.id == "REM-001") {

        const std::string configFile =
            "/etc/ssh/sshd_config.d/99-gpu-auditor.conf";

        const std::string backupFile =
            "/etc/ssh/sshd_config.d/99-gpu-auditor.conf.gpu-auditor-backup";

        std::cout
            << "  Checking existing GPU auditor SSH policy...\n";

        std::string existing =
            execCommand(
                "sudo test -f " +
                configFile +
                " && echo exists || echo missing"
            );

        bool hadExisting =
            trim(existing) == "exists";

        // ----------------------------------------------------
        // Backup an existing auditor policy
        // ----------------------------------------------------

        if (hadExisting) {

            std::cout
                << "  Existing GPU auditor policy found.\n";

            std::cout
                << "  Creating backup...\n";

            execCommand(
                "sudo cp " +
                configFile +
                " " +
                backupFile
            );

            std::string backupCheck =
                execCommand(
                    "sudo test -f " +
                    backupFile +
                    " && echo backup-ok || echo backup-failed"
                );

            if (trim(backupCheck) !=
                "backup-ok") {

                return {
                    false,
                    "Could not create backup of existing SSH policy."
                };
            }
        }

        // ----------------------------------------------------
        // Create SSH policy
        // ----------------------------------------------------

        std::cout
            << "  Creating SSH hardening policy...\n";

        const std::string createCommand =
            "printf '%s\\n' "
            "'# Managed by GPU Image Security Auditor' "
            "'# Remediation: REM-001' "
            "'PermitRootLogin no' "
            "| sudo tee " +
            configFile +
            " >/dev/null";

        execCommand(createCommand);

        // ----------------------------------------------------
        // Verify file creation
        // ----------------------------------------------------

        std::string verifyFile =
            execCommand(
                "sudo test -f " +
                configFile +
                " && echo created || echo failed"
            );

        if (trim(verifyFile) !=
            "created") {

            std::cout
                << "  Failed to create "
                << configFile
                << "\n";

            return {
                false,
                "Could not create SSH hardening policy."
            };
        }

        std::cout
            << "  SSH hardening policy created.\n";

        // ----------------------------------------------------
        // Validate sshd configuration
        // ----------------------------------------------------

        std::cout
            << "  Validating SSH configuration...\n";

        std::string syntaxResult =
            execCommand(
                "sudo sshd -t 2>&1"
            );

        if (!trim(syntaxResult).empty()) {

            std::cout
                << "  SSH configuration validation failed.\n";

            std::cout
                << syntaxResult;

            // Roll back.
            if (hadExisting) {

                execCommand(
                    "sudo cp " +
                    backupFile +
                    " " +
                    configFile
                );

            }
            else {

                execCommand(
                    "sudo rm -f " +
                    configFile
                );
            }

            return {
                false,
                "sshd -t failed. Configuration rolled back."
            };
        }

        std::cout
            << "  SSH configuration valid.\n";

        // ----------------------------------------------------
        // Verify effective configuration BEFORE reload
        // ----------------------------------------------------

        std::string effective =
            trim(
                execCommand(
                    "sudo sshd -T 2>/dev/null | "
                    "grep '^permitrootlogin '"
                )
            );

        if (effective !=
            "permitrootlogin no") {

            std::cout
                << "  Effective SSH policy is not "
                   "PermitRootLogin no.\n";

            std::cout
                << "  Current effective value: "
                << effective
                << "\n";

            // Roll back.
            if (hadExisting) {

                execCommand(
                    "sudo cp " +
                    backupFile +
                    " " +
                    configFile
                );

            }
            else {

                execCommand(
                    "sudo rm -f " +
                    configFile
                );
            }

            return {
                false,
                "SSH configuration did not produce the expected "
                "effective policy. Configuration rolled back."
            };
        }

        std::cout
            << "  Effective policy verified: "
               "permitrootlogin no\n";

        // ----------------------------------------------------
        // Reload SSH
        // ----------------------------------------------------

        std::cout
            << "  Reloading SSH service...\n";

        std::string reloadResult =
            execCommand(
                "sudo systemctl reload ssh 2>&1"
            );

        if (!trim(reloadResult).empty()) {

            std::cout
                << "  SSH reload returned:\n"
                << reloadResult;
        }

        // ----------------------------------------------------
        // Verify after reload
        // ----------------------------------------------------

        std::string postReload =
            trim(
                execCommand(
                    "sudo sshd -T 2>/dev/null | "
                    "grep '^permitrootlogin '"
                )
            );

        if (postReload !=
            "permitrootlogin no") {

            std::cout
                << "  Post-reload verification failed.\n";

            if (hadExisting) {

                execCommand(
                    "sudo cp " +
                    backupFile +
                    " " +
                    configFile
                );

            }
            else {

                execCommand(
                    "sudo rm -f " +
                    configFile
                );
            }

            execCommand(
                "sudo systemctl reload ssh 2>/dev/null"
            );

            return {
                false,
                "Post-reload verification failed. "
                "Configuration rolled back."
            };
        }

        std::cout
            << "  SSH reload successful.\n";

        std::cout
            << "  Verified: permitrootlogin no\n";

        return {
            true,
            "SSH root login disabled successfully."
        };
    }


    // --------------------------------------------------------
    // Other remediations
    // --------------------------------------------------------

    if (remediation.id == "REM-002") {

        return {
            false,
            "Not implemented in v0.5. "
            "Only REM-001 is currently supported."
        };
    }

    if (remediation.id == "REM-003") {

        return {
            false,
            "Not implemented in v0.5. "
            "Only REM-001 is currently supported."
        };
    }

    if (remediation.id == "REM-004") {

        return {
            false,
            "Not implemented in v0.5. "
            "Only REM-001 is currently supported."
        };
    }

    if (remediation.id == "REM-005") {

        return {
            false,
            "Not implemented in v0.5. "
            "Only REM-001 is currently supported."
        };
    }

    if (remediation.id == "REM-006") {

        return {
            false,
            "Not implemented in v0.5. "
            "Only REM-001 is currently supported."
        };
    }

    return {
        false,
        "Unknown remediation."
    };
}