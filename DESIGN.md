# RapidRecon - Design Flow Document

This document outlines the design and architecture of the RapidRecon network scanning and reporting tool.

## Architecture Overview

RapidRecon is built with a modular design that separates core functionality into distinct components:

```
RapidRecon/
├── rapidrecon.py         # Main entry point and CLI interface
├── scanner.py            # Network scanning functionality
├── reporter.py           # Report generation (CLI and HTML)
└── templates/            # HTML templates for reports
    └── report_template.html
```

## Component Interaction

The following diagram illustrates how components interact:

```
                                 ┌───────────────┐
                                 │ User Input    │
                                 │ (CLI Args)    │
                                 └───────┬───────┘
                                         │
                                         ▼
┌───────────────────────────────────────────────────────────────┐
│                        rapidrecon.py                           │
│                                                               │
│  - Parses command-line arguments                              │
│  - Validates input                                            │
│  - Coordinates workflow between scanner and reporter          │
└────────────────────────────┬──────────────────────────────────┘
                             │
                 ┌───────────┴────────────┐
                 │                        │
                 ▼                        ▼
┌────────────────────────────┐  ┌─────────────────────────────┐
│        scanner.py          │  │        reporter.py          │
│                            │  │                             │
│  - Host discovery          │  │  - BaseReporter class       │
│  - Port scanning           │  │  - CLIReporter class        │
│  - Service detection       │  │  - HTMLReporter class       │
│  - Risk assessment         │  │  - Report generation        │
└────────────────────────────┘  └─────────────────────────────┘
                                            │
                                            │
                                            ▼
                                ┌──────────────────────────┐
                                │ report_template.html     │
                                │ (HTML Report Template)   │
                                └──────────────────────────┘
```

## Data Flow

1. **Input Processing**:
   - User provides subnet and optional parameters via CLI args
   - `rapidrecon.py` validates the inputs and sets up the scan parameters

2. **Scanning Process**:
   - `NetworkScanner` class is initialized with scan parameters
   - Scan method is determined (nmap or socket-based)
   - Network subnet is scanned for live hosts
   - Open ports are identified on live hosts
   - Services running on open ports are detected
   - Risk levels are assigned based on service type

3. **Reporting Process**:
   - Scan results are passed to appropriate reporter (CLI, HTML, or both)
   - Reports are generated with summaries and detailed findings
   - HTML report is written to file if requested

## Key Classes and Functions

### 1. rapidrecon.py

- `parse_arguments()`: Processes command-line arguments
- `validate_subnet()`: Validates subnet format
- `main()`: Coordinates the overall workflow

### 2. scanner.py

- `NetworkScanner` class:
  - `scan()`: Main method that initiates scanning
  - `_scan_with_nmap()`: Uses python-nmap for comprehensive scanning
  - `_scan_with_socket()`: Socket-based fallback scanning
  - `_find_live_hosts()`: Identifies active hosts on the network
  - `_scan_host()`: Scans a single host for open ports

### 3. reporter.py

- `BaseReporter` class:
  - `_calculate_statistics()`: Processes scan results for reporting
  - `generate_report()`: Abstract method to be implemented by subclasses

- `CLIReporter` class:
  - `generate_report()`: Creates and displays CLI-formatted reports

- `HTMLReporter` class:
  - `generate_report()`: Creates HTML reports
  - `_generate_content()`: Produces HTML content for report
  - `_create_default_template()`: Provides a default HTML template

## Design Decisions

1. **Dual Scanning Methods**:
   - Primary: nmap-based scanning for comprehensive results
   - Fallback: Socket-based scanning when nmap is unavailable
   - Rationale: Balances functionality with portability

2. **Risk Assessment**:
   - Service-based risk categorization (High, Medium, Low)
   - Predefined risk levels for common services
   - Rationale: Provides immediate security insights without external databases

3. **Modular Architecture**:
   - Separation of scanning and reporting
   - Inheritance-based reporter design
   - Rationale: Enhances maintainability and extensibility

4. **Concurrent Scanning**:
   - Thread-based parallel scanning for socket method
   - Rationale: Improves performance on large subnets

5. **Template-Based Reporting**:
   - External HTML template
   - Fallback to embedded template if external not available
   - Rationale: Allows for customization while ensuring functionality

## Error Handling

- **Network Issues**: Graceful handling of connection errors
- **Permission Problems**: Clear error messages for privilege-related issues
- **Input Validation**: Thorough checking of subnet and port formats
- **Dependencies**: Automatic fallback if nmap is unavailable

## Performance Considerations

- Timeout parameters to control scan speed vs. thoroughness
- Thread pool for concurrent scanning with controlled resource usage
- Optional port selection to limit scan scope when needed
