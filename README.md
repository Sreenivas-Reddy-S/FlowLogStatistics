🚀 FlowLogStatistics

A super-efficient program that parses VPC flow logs and generates detailed stats based on your lookup table! 🌐💻

🌟 Assumptions

- Log Format: Only supports the default VPC flow log format – custom log formats are not supported yet!
- Version: We’re all about that VPC flow log version 2!
- Lookup Table: We expect a CSV format with the following columns: dstport, protocol, and tag.
- File Size: Handles large log files (up to 10MB) smoothly 🚀.
- Protocol Numbers: We’ve got a predefined lookup table to convert protocol numbers to names! 🔄

⚙️ Requirements

- Python 3.6+
- You know the drill – just make sure Python is installed on your system! 🐍
- 🏃 How to Run : Just hit the command line and run this: python3 main.py sample_log_file.txt sample_lookup_file.csv
- 🎯 This will process your log file and create an output in the form of output_file.txt!

📊 Output 

- After the program runs, you’ll find an output file called output_file.txt in the same directory. The output includes:

- ✅ Tag Counts: Counts for tagged entries
- ✅ Port & Protocol Counts: Matched entries broken down by port and protocol

🧪 Testing

Want to make sure it’s working like a charm? Run the test suite:

- python3 -m unittest tests.py

The tests cover:

- 🔄 Loading the lookup table
- 📝 Parsing flow logs
- 📂 Writing output to a file
- ✅ File validation
- 🚀 Large file processing (up to 10MB)

🧑‍💻 Code Analysis

- Memory Efficiency: We read the log files in chunks to save memory 🧠💾.
- Error Handling: File validation is built-in – no worries about missing or empty files!
- Flexibility: The lookup table makes it easy to configure port and protocol tagging 📊🔧.
- Scalability: The chunk reading method means the program scales easily for large files.

🚧 Limitations & Future Ideas

- IPv6 Support: Right now, we’re sticking to IPv4, but IPv6 support could be coming soon! 🌍
- Multi-threading: No parallel processing just yet – could be added for speed improvements.
- Custom Log Formats: Currently, we only support default VPC logs – let’s add more formats in the future!
- Output Flexibility: Right now, we’re using fixed output format. We could definitely add CSV/JSON options next! 🔄

✨ Ready to go? Clone the repo and let’s get parsing!

🚀 Getting Started

- 1️⃣ Clone the repo: git clone https://github.com/Sreenivas-Reddy-S/FlowLogStatistics.git
- 2️⃣ Run the program following the instructions in README.md and you'll be processing logs like a pro!

💬 Need help? Drop me a message and let’s make this work for you! 😊
