#include <string>
#include <vector>

enum class Severity {
    PASS,
    INFO,
    WARN,
    HIGH
};

struct Finding {
    std::string id;
    Severity severity;
    std::string title;
    std::string details;
    int points;
};

struct SystemInfo {
    std::string os;
    std::string kernel;
    std::string gpu;
    std::string driver;
    std::string cuda;
};

struct Listener {
    std::string protocol;
    std::string address;
    int port;
    std::string process;
    bool externallyBound;
};

// SSH activity
struct SSHSession {
    std::string user;
    std::string terminal;
    std::string source;
    std::string loginTime;
};

struct SSHLogin {
    std::string user;
    std::string source;
    std::string loginTime;
    std::string duration;
};

struct SSHFailedAttempt {
    std::string user;
    std::string source;
    std::string attemptTime;
};

// Remediation
struct Remediation {
    std::string id;
    std::string findingId;
    std::string title;
    std::string description;
    Severity risk;
    bool requiresReboot;
    bool requiresSudo;
};

struct RemediationResult {
    bool success;
    std::string message;
};

SystemInfo collectSystemInfo();
std::vector<Listener> collectListeners();

std::vector<SSHSession> collectCurrentSSHSessions();
std::vector<SSHLogin> collectSSHLoginHistory(int limit = 10);
std::vector<SSHFailedAttempt> collectSSHFailedAttempts(int limit = 10);

std::vector<Finding> runChecks(
    const std::vector<Listener>& listeners);

std::string severityToString(Severity severity);

int calculateScore(
    const std::vector<Finding>& findings);

// Remediation
std::vector<Remediation> generateRemediations(
    const std::vector<Finding>& findings);

void printRemediationPlan(
    const std::vector<Remediation>& remediations);

RemediationResult enforceRemediation(
    const Remediation& remediation);