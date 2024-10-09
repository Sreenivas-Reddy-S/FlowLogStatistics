# FlowLogStatistics
This program is designed to parse flow logs and generate statistics based on a provided lookup table. It processes large log files efficiently and provides counts for tagged and untagged entries.

## Assumptions
1. Log Format: The program only supports the default VPC flow log format. Custom log formats are not supported.
2. Version: Only version 2 of the VPC flow log format is supported.
3. Lookup Table: The lookup table is expected to be in CSV format with columns: dstport, protocol, and tag.
4. File Size: The program is designed to handle large log files (tested up to 10MB) efficiently.
5. Protocol Numbers: The program uses a predefined lookup table for protocol numbers to names conversion.

## Requirements
- Python 3.6 or higher

# To Run the file, use following commands.
python main.py <flow_logs_file.txt> <lookup_file.csv>
Here it is : python main.py sample_flow_logs.txt sample_lookup_table.csv 

## Output
The program generates an output file named `output_file.txt` in the same directory. This file contains:
1. Tag counts
2. Port and protocol counts for matched entries

## Testing
To run the tests, use the following command:
python -m unittest tests.py

The test suite includes:
1. Testing the loading of the lookup table
2. Parsing of flow logs
3. Writing output to a file
4. File validation
5. Large file processing (up to 10MB)

## Code Analysis
1. Memory Efficiency: The program reads large files in chunks to avoid loading the entire file into memory.
2. Error Handling: The program includes validation for file existence and non-empty files.
3. Flexibility: The lookup table allows for easy configuration of port and protocol tagging.
4. Scalability: The chunked reading approach allows for processing of very large log files.

## Limitations and Future Improvements
1. Currently only supports IPv4 addresses. IPv6 support could be added in the future.
2. The program doesn't handle multi-threading for parallel processing of large files.
3. Custom log formats are not supported and could be added for more flexibility.
4. The output format is fixed. Future versions could support multiple output formats (e.g., CSV, JSON).
