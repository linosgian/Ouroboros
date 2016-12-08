# Ouroboros

Ouroboros is a malware built for educational purposes only. At the time of writing, it goes undetected under Windows Defender.
Tested under Windows XP,7,8.1 and 10.

## Infect Method
  1. Send the VB Macro in a form of a .doc file
  2. Lure the victim into enabling macros.

## Built With

* [Visual C++](https://support.microsoft.com/en-us/kb/2977003) 
* [B-Con's Crypto Library](https://github.com/B-Con/crypto-algorithms)  

- Stack with C-Style code instead of pure C++.
- Not following the golden rule *DO NOT ROLL YOUR OWN CRYPTO*, i used a non-standard sha256 implementation because of:
  * Annoying dependencies and size of OpenSSL library.
  * Extremely verbose code of Win32API's Crypto library.
  * I only needed SHA256 for hashing one single usage. To produce a mutex in order to avoid multiple instance of the malware running at the same time
In any case what i've done is NOT recommended.

## Main Ideas

The malware does not do anything new nor does it exploit a new/unknown vulnerability. As stated above, it was developed for educational purposes.
  1. DLL Injection - Old school dll injection:
    1. Allocate memory for the DLL's path
    2. Store the string containing it
    3. Load the library and get the Base Address
    4. Find the exported function's RVA and resolve its actual VA on the remote process' VM.
    5. Execute the exported function in the remote process.
  2. KeyLogging:
    + Using the typical WH_KEYBOARD_LL hook to intercept the keystrokes.
    + Custom-made lookup tables for performance optimization and code compaction and readability
    + Periodically checking the ForegroundWindow in order to get a sense of where the victim sends his keystrokes to.
    + Registering a HOTKEY combination that stops the keylogger
    + Capture a screenshot when the user presses PrtScrn Button ( VK_SNAPSHOT )
  3. Reverse Shell:
    + Straightforward redirection of stdout/stdin/stderr streams to a socket, in order to connect to the C&C Server.
  4. Mutual Exclusion:
    1. Gather information about the infected machine ( GPU-CPU info, Computer Name, Screen Resolution, Number of Processors.
    2. Salt used to avoid the usage of rainbow tables.
    3. Concat all the information and put them through the sha256 function. This way we make sure we don't go over the MAX_PATH limit on Mutexes
  5. General Algorithm:
    1. Execute the VB Macro:
      1. Downloads the crypto32.dll
      2. Writes a /Run Registry Key
      3. Executes the #2 ( ordinal ) function of the dll.
    2. Executing the #2 Function:
      1. Iterate through all the processes on the infected machine in order to find a 32-bit target.
      2. Attempt to open the candidate target process with the right privileges.
      3. If it was a success, try to inject that process.
      4. If the injection failed ( mostly due to suspended processes ), go to step (b).


 
