# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.2] - 2023-10-04

### Changed

- Added "-E" to router-registration alias
- add new line to end of ziti version print statement

## [1.5.1] - 2023-09-15

### Fixed

bugfix: changed pid flag to versions above 0.27.9

## [1.5.0] - 2023-09-13

### Changed

- Added ziti auto complete

## [1.4.4] - 2023-09-13

### Fixed

- Added pid flag to agent commands for version above 0.28.0.

## [1.4.3] - 2023-07-14

### Fixed

- nfhelp commands
    - `diverter-enable`  - updated diverter-enable command to restart the ziti-edge-router every time

## [1.4.2] - 2023-07-13

### Added

- nfhelp commands
    - `zt-erhchecker-update`  - download/update hc checker script that can be used by program like vrrp to evaluate the state of the edge-router

## [1.4.1] - 2023-06-28

### Changed

- Switched ip helper to ipinfo.io instead of ipify.org

## [1.4.0] - 2023-06-28

### Changed

- nfhelp commands
    - `diverter-...`  - all diverter aliases were updated to the new ebpf bytecode, i.e. zfw(-router) from ebpf-tproxy-splicer

## [1.3.3] - 2023-05-02

### Fixed

- nfhelp commands
    - `diverter-update`  - updated diverter-update command to not use command alias but actual command to check for current ziti version

## [1.3.2] - 2023-03-13

### Fixed

- nfhelp commands
    - `diverter-update`  - running this command would result in an error; logic to check for version has been moved to the function. Internal task: CLOUDDEV-1110

## [1.3.1] - 2023-03-08

### Changed

- nfhelp commands
    - `diverter-update`  - added logic to check for the minimum ziti version required to run ebpf, i.e. `if [[ "${ZITI_CLI_VERSION}" > "0.27.2" ]]; then diverter_update... `

## [1.3.0] - 2023-02-15

### Changed

 - Updated logic to handle single ziti binary - basing all functions on ziti cli version.
 - Updated pid commands from using `pidof` to `systemctl`

## [1.2.2] - 2023-02-13

### Changed

- nfhelp commands
    - `diverter-update`         - updated the help message to include memory size requirement

### Added

- nfhelp commands
    - `etables`                 - link to the etables program used to manage ebpf map content

## [1.2.1] - 2023-02-10

### Added

- nfhelp commands
    - `diverter-map-add`       - add all user ingress rules to ebpf map
    - `diverter-map-delete`    - delete all user ingress rules from ebpf map
    - `diverter-trace`         - show ebpf trace logs

## [1.2.0] - 2023-02-03

### Changed

- nfhelp commands
    - `diverter-update`         - update the iptables diverter binary to latest version with the map table size option
        - `--small`             - 1000 map entries
        - `--medium`            - 5000 map entries
        - `--large`             - 10000 map entries
    - `zt-intercepts`           - added ability to list intercepts based on the data source (i.e. iptables, ebpf map)
    - `zt-firewall-rules`    - added ability to list rules based on the data source (i.e. iptables, ebpf map)

### Added

- nfhelp command
    - `diverter-map`            - user space program to access ebpf map

## [1.1.1] - 2023-01-31

- bugfix: PS_COMMAND renamed to STACK_COMMAND & adjusted for versions above 0.26.11 - 
- bugfix: Determining which CLI command is now based on CLI version instead of Router

## [1.1.0] - 2023-01-30

### Added 

- nfhelp commands
    - `diverter-enable`     - enable iptables diverter ebpf program
    - `diverter-disable`    - disable iptables diverter ebpf program
    - `diverter-status`     - check if iptables diverter ebpf program is enabled
    - `diverter-update`     - update the iptables diverter binary to latest version

## [1.0.2] - 2023-01-26

- bugfix: fixed paths to binaries(support/register/upgrade)

## [1.0.1] - 2023-01-25

- bugfix: check to make sure cli exists before print out information

## [1.0.0] - 2023-01-09

- Initial version
