#pragma once

//Make it cleaner.
namespace Injection 
{
	bool CreatedSuspendedProcess(TargetProcess* proc) noexcept;
	bool CreateAndRelocateDllInRemoteProcess(TargetProcess* process) noexcept;
	void MainExecFunction() noexcept;
	bool HookEntrypointFunction(TargetProcess* process);

};