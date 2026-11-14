# From filing to bench plan

## Components and technical sources

For each part, record location/reference designator, exact visible marking, manufacturer/part candidate, role, primary documentation, and confidence. Check suffix/package differences. Do not confuse module marking with enclosed SoC, or crystal frequency with CPU clock. Infer architecture, storage, logic levels, and debug features from exact-part and board evidence; a family datasheet need not fix the fitted option or security state.

Search vendor datasheets, design guides, reference boards, SDK/boot documentation, support pages, and public source/firmware releases. Then check exact revisions in original teardown repositories, OpenWrt/alternative firmware projects, and Linux driver sources where relevant. Chipset support alone does not establish working support for a retail board. Do not call firmware flashable until model, region, revision, partition layout, and recovery path match.

## Interface reasoning

| Candidate | Useful evidence | First validation | Avoid assuming |
| --- | --- | --- | --- |
| UART | Labeled pads, schematic, exact pin map, boot log | Confirm ground/idle voltage; passively capture target TX | Pin order, 115200 baud, console access, 5 V tolerance |
| SWD/JTAG | Schematic, mux docs, debug header | Confirm reference voltage, routing, probe mode | Exposed means unlocked; connection cannot change storage |
| SPI NOR | Exact marking/datasheet, routing | Establish supply/I/O voltage and bus isolation | Every eight-pin part is 3.3 V flash; clips ensure reliable reads |
| eMMC/NAND | Exact package, pads, schematic, controller docs | Establish signals/voltages and read path | UART grants storage access or arbitrary partition layouts apply |
| USB | Routing, descriptors/VID/PID, boot docs | Inspect enumeration and documented recovery | Connector carries data or accepts arbitrary firmware |
| I²C/SPI/sensors | Chip docs, pull-ups, traces | Passive capture with compatible voltage | Bus is safe to drive while the host is active |
| RF connector | Schematic/mechanical identification | Confirm role, path, levels, receiver band | Every coax/test port is an antenna or SDR-safe |

Give an oriented pin table only when supported; mark candidates and unknowns. Do not connect adapter VCC by default. For UART, confirm ground with power off, measure signal/reference voltage in a valid operating condition, then connect only ground and a compatible receiver for first capture. Distinguish TTL UART from RS-232. Derive baud from documentation or captured bit period; label guesses.

Before external storage reads, identify the part/voltage, isolate competing bus drivers, and prevent back-powering. Use one deliberate power path. Take independent reads and compare hashes before treating a dump as a backup. Preserve calibration, MAC/NVRAM, keys, bootloader, and partition data; redact device-specific secrets in shared reports. Do not select voltage, programmer, or flash commands from package shape alone.

Check documented read protection, secure boot, flash encryption, OTP/eFuses, signed updates, and anti-rollback; report unknown states as **unknown**. Check tool defaults: unlocking protected MCUs may mass-erase them. Do not suggest unlock/erase/fuse changes as an exploratory first step. For invasive/destructive routes, explain the actual dependency/risk and rank other evidence sources first.

For mains/high-energy hardware, identify the specific isolation/power hazard before probe connections. Do not attach a grounded USB probe/scope to an unverified non-isolated mains reference. Tie precautions to the proposed measurement; avoid generic warning boilerplate.

## Firmware and local control

- Prefer public firmware, documented recovery, boot logs, and read-only acquisition. Verify origin/model/region/revision and record hashes.
- Analyze without executing vendor binaries/extracted scripts. Use `file`, `xxd`, `strings`, `binwalk`, filesystem extractors, and device-tree tools where formats and installed versions warrant them. Check current primary tool docs before relying on changing syntax.
- Distinguish compression, encryption, signing, and unidentified data. A signature header or high entropy alone does not prove enforcement or encryption.
- Map architecture, containers/partitions, bootloader, OS/filesystems, services, cloud dependencies, update URLs, and config storage when supported. Redact secrets/unique identifiers in shared output.
- Evaluate local control/self-hosting against actual protocols, firmware support, and recovery constraints. State what still requires capture on the user's own device or isolated test network.

## Radio interpretation

Record actual tested bands/channels, evidenced modes, channel width, modulation, antenna gain/type, and power with units and basis (conducted, ERP/EIRP, peak/average). Do not mix dBm/watts, conducted/radiated power, or silicon maxima/board measurements. Note test conditions and host-specific reductions.

Treat FCC measurements as RF/certification evidence, not a full protocol specification. State what packet capture, passive SDR, or logic analysis would resolve. Match receiver frequency range, bandwidth, sample rate, modulation capability, and input rating to the signal before recommending hardware/commands. Separate reception from transmission; verify current relevant rules when a proposed transmit experiment requires it.

## Rank concrete experiments

For each action give objective, evidence needed, equipment, supported wiring/commands, expected observation, decision point, and reversibility. Choose the smallest experiment that resolves an uncertainty: sharper marking, revision match, boot TX capture, USB descriptors, verified storage backup, or passive radio observation. Avoid padding unsupported dossiers with every possible technique.
