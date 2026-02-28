# keyauth library (hardened build by nigel)

this repo keeps keyauth api behavior compatible while adding stronger local security hardening.

## maintainer
- name: nigel
- discord: chefendpoint

## quick notes
- api surface kept compatible
- auth flow kept compatible
- security internals upgraded
- comments use `// ... -nigel` format for changed areas

## security change bullets
- replaced shell-based hashing path with in-process hashing
- fixed `thash` behavior to send hash value instead of file path
- added strict https-only transport guardrails
- added strict url sanitation before requests
- added signed-response enforcement in request path
- added stricter signature and timestamp header validation
- added request and response size limits
- added safer json parsing with fail-closed behavior
- added secure string cleanup for sensitive payloads
- added dpapi protection for local seed file writes
- upgraded random generation path for seed creation
- strengthened section integrity checking reliability
- improved lockmemaccess safety and cleanup behavior
- hardened modify loop with guarded thresholds
- added debugger and environment heartbeat checks
- prevented repeated veh handler stacking in emulator protection
- rebuilt xor string layer with stronger custom key schedule
- added xor object zeroization behavior on teardown
- fixed xor constructor init list to avoid msvc initializer error
- fixed xor key part cast to avoid msvc parse error
- restored xor key mask using numeric_limits max() call
- fixed unsafe web login reason-string lifetime bug
- fixed optional path logic bug (`!path.empty()`)
- added suspicious module detection in modify loop
- refined writable `.text` page detection (exec+writable only)
- added localhost host and loopback validation for web_login requests
- fixed build includes for dpapi + winsock types
- tightened transport runtime flags (no netrc/auth/cookies)

## emulator / anti-tamper updates
- `killEmulator.hpp` now installs veh once via `std::call_once`
- added process blacklist checks for common vm/debug tools
- added debugger presence checks (local + remote)
- added low-resource and hypervisor weighted risk checks
- added heartbeat gate for repeated local environment checks
- added safer pointer/context guards inside exception handler
- added process checks for common hook/debug usermode modules

## build (windows)
- open `library.sln` in visual studio
- build `release | x64` (or x86 if needed)
- project expects static curl/libsodium setup in project config

## support
- this fork is focused on hardening and local protection quality
- for api usage details, follow keyauth cpp example docs
