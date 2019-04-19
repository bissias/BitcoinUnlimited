#include "electrum/electrumserver.h"
#include "electrum/electrs.h"
#include "util.h"
#include "utilprocess.h"

#include <chrono>
#include <string>

//! give the program a second to complain about startup issues, such as invalid
//! parameters.
static bool startup_check(const SubProcess &p)
{
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(1s);
    if (p.IsRunning())
    {
        // process hasn't exited, good.
        return true;
    }
    LOGA("Electrum: startup check failed, server exited within 1 second");
    return false;
}

static void log_args(const std::string &path, const std::vector<std::string> &args)
{
    if (!Logging::LogAcceptCategory(ELECTRUM))
    {
        return;
    }

    std::stringstream ss;
    ss << path;
    for (auto &a : args)
    {
        ss << " " << a;
    }
    LOGA("Electrum: spawning %s", ss.str());
}

namespace electrum
{
ElectrumServer::ElectrumServer() {}
ElectrumServer::~ElectrumServer()
{
    if (started)
        Stop();
}

//! called when electrs produces a line in stdout/stderr
static void callb_logger(const std::string &line) { LOGA("Electrum: %s", line); }
bool ElectrumServer::Start(int rpcport, const std::string &network)
{
    DbgAssert(!started, return false);
    if (!GetBoolArg("-electrum", false))
    {
        LOGA("Electrum: Disabled. Not starting server.");
        return true;
    }

    auto path = electrs_path();
    auto args = electrs_args(rpcport, network);
    log_args(path, args);
    process.reset(new SubProcess(path, args, callb_logger, callb_logger));

    process_thread = std::thread([this]() {
        LOGA("Electrum: Starting server");
        try
        {
            this->process->Run();
        }
        catch (const subprocess_error &e)
        {
            LOGA("Electrum: Server not running: %s, exit status %d, termination signal %d", e.what(), e.exit_status,
                e.termination_signal);
        }
        catch (...)
        {
            LOGA("Electrum: Unknown error running server");
        }
    });
    started = true;
    return startup_check(*process);
}

static void stop_server(SubProcess &p)
{
    if (!p.IsRunning())
    {
        return;
    }
    LOGA("Electrum: Stopping server");

    try
    {
        p.Interrupt();
    }
    catch (const subprocess_error &e)
    {
        LOGA("Electrum: %s", e.what());
        p.Terminate();
        return;
    }

    using namespace std::chrono_literals;
    using namespace std::chrono;

    auto timeout = 60s;
    auto start = system_clock::now();
    while (p.IsRunning())
    {
        if ((system_clock::now() - start) < timeout)
        {
            std::this_thread::sleep_for(1s);
            continue;
        }
        LOGA("Electrum: Timed out waiting for clean shutdown (%s seconds)", timeout.count());
        p.Terminate();
        return;
    }
}

void ElectrumServer::Stop()
{
    if (!started)
    {
        return;
    }
    try
    {
        stop_server(*process);
    }
    catch (const std::exception &e)
    {
        LOGA("Electrum: Error stopping server %s", e.what());
    }
    process_thread.join();
    started = false;
}

ElectrumServer &ElectrumServer::Instance()
{
    static ElectrumServer instance;
    return instance;
}

} // ns electrum