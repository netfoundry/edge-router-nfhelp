# Changelog

All notable changes to this project will be documented in this file. The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2023-01-09

- Initial version

## [1.0.1] - 2023-01-25

- bugfix: check to make sure cli exists before print out information

## [1.0.2] - 2023-01-26

- bugfix: fixed paths to binaries(support/register/upgrade)

## [1.1.0] - 2023-01-30

### Added 

- New nfhelp commands
    - `diverter-enable`     - enable iptables diverter ebpf program
    - `diverter-disable`    - disable iptables diverter ebpf program
    - `diverter-status`     - check if iptables diverter ebpf program is enabled
    - `diverter-update`    - update the iptables diverter binary to latest version

## [1.1.1] - 2023-01-31

- bugfix: PS_COMMAND renamed to STACK_COMMAND & adjusted for versions above 0.26.11 - 
- bugfix: Determining which CLI command is now based on CLI version instead of Router

