#include "checks.h"

#include <iostream>
#include <string>
#include <vector>


namespace {

void printSeparator()
{
    std::cout
        << "----------------------------------------\n";
}


void printFinding(
    const Finding& finding)
{
    std::cout
        << "["
        << severityToString(
               finding.severity)
        << "] "
        << finding.id
        << " "
        << finding.title
        << "\n";

    if (!finding.details.empty()) {

        std::cout
            << "    "
            << finding.details
            << "\n";
    }
}


void printListener(
    const Listener& listener)
{
    std::cout
        << listener.protocol
        << " "
        << listener.address
        << ":"
        << listener.port;

    if (!listener.process.empty()) {

        std::cout
            << " ("
            << listener.process
            << ")";
    }

    if (listener.externallyBound) {

        std::cout
            << " [EXTERNAL]";
    }
    else {

        std::cout
            << " [LOOPBACK]";
    }

    std::cout << "\n";
}


void printUsage(
    const char* program)
{
    std::cout
        << "\nGPU Image Security Auditor\n"
        << "==========================\n\n"

        << "Usage:\n"
        << "  "
        << program
        << " audit\n"
        << "  "
        << program
        << " plan\n"
        << "  "
        << program
        << " enforce\n"
        << "  "
        << program
        << " --help\n\n"

        << "Commands:\n"
        << "  audit    Run security audit only.\n"
        << "  plan     Show available remediation actions.\n"
        << "  enforce  Apply supported remediation actions.\n";
}


void printAudit()
{
    std::cout
        << "\nGPU IMAGE SECURITY AUDITOR\n";

    printSeparator();

    // --------------------------------------------------------
    // SYSTEM
    // --------------------------------------------------------

    SystemInfo system =
        collectSystemInfo();

    std::cout
        << "\nSYSTEM\n";

    printSeparator();

    std::cout
        << "OS:     "
        << system.os
        << "\n";

    std::cout
        << "Kernel: "
        << system.kernel
        << "\n";

    std::cout
        << "GPU:    "
        << system.gpu
        << "\n";

    std::cout
        << "Driver: "
        << system.driver
        << "\n";

    std::cout
        << "CUDA:   "
        << system.cuda
        << "\n";


    // --------------------------------------------------------
    // SSH ACTIVITY
    // --------------------------------------------------------

    std::cout
        << "\nSSH ACTIVITY\n";

    printSeparator();

    std::vector<SSHSession> sessions =
        collectCurrentSSHSessions();

    std::cout
        << "CURRENT SESSIONS\n";

    if (sessions.empty()) {

        std::cout
            << "  None detected.\n";
    }
    else {

        for (const SSHSession& session :
             sessions) {

            std::cout
                << "  "
                << session.user
                << " "
                << session.terminal
                << " "
                << session.source
                << " "
                << session.loginTime
                << "\n";
        }
    }


    std::vector<SSHLogin> logins =
        collectSSHLoginHistory(10);

    std::cout
        << "\nRECENT LOGIN HISTORY\n";

    if (logins.empty()) {

        std::cout
            << "  No login history detected.\n";
    }
    else {

        for (const SSHLogin& login :
             logins) {

            std::cout
                << "  "
                << login.user
                << " "
                << login.source
                << " "
                << login.loginTime
                << "\n";
        }
    }


    std::vector<SSHFailedAttempt> failedAttempts =
        collectSSHFailedAttempts(10);

    std::cout
        << "\nRECENT FAILED SSH ATTEMPTS\n";

    if (failedAttempts.empty()) {

        std::cout
            << "  None detected.\n";
    }
    else {

        for (const SSHFailedAttempt& attempt :
             failedAttempts) {

            std::cout
                << "  "
                << attempt.user
                << " "
                << attempt.source
                << " "
                << attempt.attemptTime
                << "\n";
        }
    }


    // --------------------------------------------------------
    // NETWORK
    // --------------------------------------------------------

    std::vector<Listener> listeners =
        collectListeners();

    std::cout
        << "\nNETWORK LISTENERS\n";

    printSeparator();

    if (listeners.empty()) {

        std::cout
            << "No listeners detected.\n";
    }
    else {

        for (const Listener& listener :
             listeners) {

            printListener(listener);
        }
    }


    // --------------------------------------------------------
    // SECURITY FINDINGS
    // --------------------------------------------------------

    std::vector<Finding> findings =
        runChecks(listeners);

    std::cout
        << "\nSECURITY FINDINGS\n";

    printSeparator();

    int passCount = 0;
    int infoCount = 0;
    int warnCount = 0;
    int highCount = 0;

    for (const Finding& finding :
         findings) {

        printFinding(finding);

        switch (finding.severity) {

            case Severity::PASS:
                ++passCount;
                break;

            case Severity::INFO:
                ++infoCount;
                break;

            case Severity::WARN:
                ++warnCount;
                break;

            case Severity::HIGH:
                ++highCount;
                break;
        }
    }


    // --------------------------------------------------------
    // SCORE
    // --------------------------------------------------------

    int score =
        calculateScore(findings);

    std::cout
        << "\nSECURITY SCORE: "
        << score
        << "/100\n";

    std::cout
        << "PASS: "
        << passCount
        << "  INFO: "
        << infoCount
        << "  WARN: "
        << warnCount
        << "  HIGH: "
        << highCount
        << "\n";
}


std::vector<Remediation>
getCurrentRemediations()
{
    std::vector<Listener> listeners =
        collectListeners();

    std::vector<Finding> findings =
        runChecks(listeners);

    return generateRemediations(findings);
}


void runPlan()
{
    std::cout
        << "\nGENERATING REMEDIATION PLAN\n";

    printSeparator();

    std::vector<Remediation> remediations =
        getCurrentRemediations();

    printRemediationPlan(remediations);
}


void runEnforcement()
{
    std::cout
        << "\nSTARTING ENFORCEMENT\n";

    printSeparator();

    std::vector<Remediation> remediations =
        getCurrentRemediations();

    if (remediations.empty()) {

        std::cout
            << "No remediation actions required.\n";

        return;
    }

    printRemediationPlan(remediations);

    std::cout
        << "\nWARNING: This will modify the system.\n"
        << "Supported remediation(s) may change SSH configuration.\n"
        << "A backup will be created before modification.\n\n";

    std::cout
        << "Continue? [y/N]: ";

    std::string answer;

    std::getline(
        std::cin,
        answer
    );

    if (answer != "y" &&
        answer != "Y") {

        std::cout
            << "\nEnforcement cancelled.\n";

        return;
    }


    bool anythingApplied = false;

    for (const Remediation& remediation :
         remediations) {

        std::cout
            << "\nENFORCING: "
            << remediation.id
            << "\n"
            << remediation.title
            << "\n";

        RemediationResult result =
            enforceRemediation(
                remediation
            );

        if (result.success) {

            anythingApplied = true;

            std::cout
                << "\n[APPLIED] "
                << remediation.id
                << " "
                << result.message
                << "\n";

        }
        else {

            std::cout
                << "\n[NOT APPLIED] "
                << remediation.id
                << " "
                << result.message
                << "\n";
        }
    }


    // --------------------------------------------------------
    // Post-enforcement audit
    // --------------------------------------------------------

    std::cout
        << "\nPOST-ENFORCEMENT AUDIT\n";

    printSeparator();

    std::vector<Listener> listeners =
        collectListeners();

    std::vector<Finding> findings =
        runChecks(listeners);

    for (const Finding& finding :
         findings) {

        printFinding(finding);
    }

    int score =
        calculateScore(findings);

    std::cout
        << "\nNew Security Score: "
        << score
        << "/100\n";

    if (anythingApplied) {

        std::cout
            << "\nEnforcement completed. "
               "Review the post-enforcement audit above.\n";
    }
}

} // namespace


// ============================================================
// MAIN
// ============================================================

int main(int argc, char* argv[])
{
    std::string command = "audit";

    if (argc >= 2) {
        command = argv[1];
    }

    if (command == "--help" ||
        command == "-h") {

        printUsage(argv[0]);
        return 0;
    }

    if (command == "audit") {

        printAudit();
        return 0;
    }

    if (command == "plan") {

        runPlan();
        return 0;
    }

    if (command == "enforce") {

        runEnforcement();
        return 0;
    }

    std::cerr
        << "Unknown command: "
        << command
        << "\n";

    printUsage(argv[0]);

    return 1;
}