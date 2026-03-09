# Developer Contribution Guidelines

This guide is intended for developers who wish to extend or modify the implant's functionality.

---

## 1. Coding Standards

- **Namespace Architecture**: All code must reside within the appropriate namespace (e.g., `lateral`, `credential`, `evasion`). Avoid polluting the global namespace.
- **String Obfuscation**: Never include sensitive plaintext strings in the source code.
    - Use the `encode_helper` utility (found in project history) to generate XORed hex arrays.
    - Example: `const wchar_t kSecret[] = { L'S'^0x4B, L'e'^0x1F, ... };`
- **Error Handling**: Use the central `LOG_DEBUG`, `LOG_INFO`, and `LOG_ERR` macros for diagnostic output. Avoid printing directly to `stdout`.

---

## 2. Implementing a New Task

To add a new feature triggered by the C2:

1.  **Define Task ID**: Add a unique string identifier in `src/beacon/Beacon.cpp`'s `stringToTaskType` function.
2.  **Add Enum**: Add a corresponding entry to the `TaskType` enum in `src/beacon/Task.h`.
3.  **Implement Logic**: Create your logic in a new or existing module directory.
4.  **Route Task**: Add a case to the switch statement in `src/beacon/TaskDispatcher.cpp` to call your implementation.
5.  **Return Results**: Package the output into a `Result` object and enqueue it.

---

## 3. Security Considerations

- **Thread Safety**: The `TaskDispatcher` spawns a new thread for every incoming task. Ensure all global or shared resources are properly protected or synchronized.
- **Resource Management**: Always release Windows API handles (`CloseHandle`, `CloseServiceHandle`) and COM objects (`Release()`) to prevent resource exhaustion.
- **Evasion Hygiene**: Avoid suspicious API calls (e.g., `CreateRemoteThread`) where possible. Use the indirect syscall wrappers provided in `evasion/Syscalls.h`.

---

## 4. Submission Process

1.  Create a feature branch.
2.  Implement changes following the standards above.
3.  Run the crypto and utility unit tests (`unit_tests` executable).
4.  Ensure the code compiles with both MSVC and MinGW.
5.  Submit a detailed Pull Request.
