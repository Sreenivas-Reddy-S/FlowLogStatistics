import unittest
import os
import tempfile
import shutil
import csv
import random
from main import load_lookup_table, parse_flow_logs, write_output_to_file, validate_file


class TestFlowLogParser(unittest.TestCase):

    def setUp(self):
        """
        Set up the test environment.
        Creates a temporary directory and sample files for testing.
        """
        # Create temporary directory for testing
        self.temp_dir = tempfile.mkdtemp()

        # Create a large dummy_logs.txt (approximately 10 MB)
        self.dummy_logs_path = os.path.join(self.temp_dir, 'dummy_logs.txt')
        self._create_large_log_file(self.dummy_logs_path, target_size_mb=10)

        # Create a large dummy.csv with up to 10000 mappings
        self.dummy_csv_path = os.path.join(self.temp_dir, 'dummy.csv')
        self.num_mappings = self._create_large_lookup_file(self.dummy_csv_path, num_mappings=10000)

    def tearDown(self):
        """
        Clean up the test environment.
        Removes the temporary directory and all its contents.
        """
        shutil.rmtree(self.temp_dir)

    def _create_large_log_file(self, file_path, target_size_mb=10):
        """
        Create a large log file for testing.

        Args:
            file_path (str): Path to create the file.
            target_size_mb (int): Approximate target file size in MB.
        """
        log_entry_template = "{} {} eni-{} {}.{}.{}.{} {}.{}.{}.{} {} {} {} {} {} {} {} {} {}\n"

        with open(file_path, 'w') as f:
            while os.path.getsize(file_path) < target_size_mb * 1024 * 1024:
                log_entry = log_entry_template.format(
                    random.randint(1, 5),
                    ''.join([str(random.randint(0, 9)) for _ in range(12)]),
                    ''.join([random.choice('0123456789abcdef') for _ in range(8)]),
                    *[random.randint(1, 255) for _ in range(8)],
                    random.randint(1, 65535),
                    random.randint(1, 65535),
                    random.randint(1, 255),
                    random.randint(1, 1000),
                    random.randint(1000, 10000),
                    int(random.uniform(1600000000, 1700000000)),
                    int(random.uniform(1600000000, 1700000000)),
                    random.choice(['ACCEPT', 'REJECT']),
                    'OK'
                )
                f.write(log_entry)

    def _create_large_lookup_file(self, file_path, num_mappings=10000):
        """
        Create a large lookup file for testing.

        Args:
            file_path (str): Path to create the file.
            num_mappings (int): Number of mappings to create.

        Returns:
            int: Actual number of unique mappings created.
        """
        unique_mappings = set()
        with open(file_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['dstport', 'protocol', 'tag'])

            while len(unique_mappings) < num_mappings:
                mapping = (
                    random.randint(1, 65535),
                    random.choice(['tcp', 'udp']),
                    f"sv_P{random.randint(1, 100)}"
                )
                if mapping not in unique_mappings:
                    unique_mappings.add(mapping)
                    writer.writerow(mapping)

        return len(unique_mappings)

    def test_load_lookup_table(self):
        """Test if the lookup table is correctly loaded from the CSV file."""
        lookup_table = load_lookup_table(self.dummy_csv_path)

        # Count unique entries in the CSV file
        unique_entries = set()
        with open(self.dummy_csv_path, 'r') as f:
            csv_reader = csv.reader(f)
            next(csv_reader)  # Skip header
            for row in csv_reader:
                unique_entries.add((int(row[0]), row[1]))

        self.assertEqual(len(lookup_table), len(unique_entries))
        self.assertTrue(all(isinstance(k, tuple) and len(k) == 2 for k in lookup_table.keys()))
        self.assertTrue(all(isinstance(v, str) for v in lookup_table.values()))

    def test_parse_flow_logs(self):
        """Test if flow logs are parsed correctly and counts are accurate."""
        lookup_table = load_lookup_table(self.dummy_csv_path)
        tag_counts, port_protocol_counts = parse_flow_logs(self.dummy_logs_path, lookup_table)

        self.assertGreater(len(tag_counts), 0)
        self.assertGreater(len(port_protocol_counts), 0)
        self.assertIn('Untagged', tag_counts)

    def test_write_output_to_file(self):
        """Test if the output is written to a file in the correct format."""
        tag_counts = {'sv_P1': 1000, 'sv_P2': 500, 'Untagged': 8500}
        port_protocol_counts = {(80, 'tcp'): 1000, (443, 'tcp'): 500}

        output_path = os.path.join(self.temp_dir, 'test_output.txt')
        write_output_to_file(tag_counts, port_protocol_counts, output_path)

        with open(output_path, 'r') as f:
            content = f.read()

        self.assertIn('Tag Counts:', content)
        self.assertIn('sv_P1,1000', content)
        self.assertIn('sv_P2,500', content)
        self.assertIn('Untagged,8500', content)
        self.assertIn('Port,Protocol,Count', content)
        self.assertIn('80,tcp,1000', content)
        self.assertIn('443,tcp,500', content)

    def test_validate_file_exists(self):
        """Test if file validation works for existing files."""
        validate_file(self.dummy_logs_path)  # Should not raise an exception

    def test_validate_file_not_exists(self):
        """Test if file validation raises an error for non-existent files."""
        with self.assertRaises(SystemExit):
            validate_file(os.path.join(self.temp_dir, 'non_existent_file.txt'))

    def test_validate_file_empty(self):
        """Test if file validation raises an error for empty files."""
        empty_file_path = os.path.join(self.temp_dir, 'empty.txt')
        with open(empty_file_path, 'w') as f:
            pass  # Create an empty file

        with self.assertRaises(SystemExit):
            validate_file(empty_file_path)

    def test_large_file_processing(self):
        """Test if the script can handle processing of large files."""
        lookup_table = load_lookup_table(self.dummy_csv_path)
        tag_counts, port_protocol_counts = parse_flow_logs(self.dummy_logs_path, lookup_table)

        self.assertGreater(len(tag_counts), 0)
        self.assertGreater(len(port_protocol_counts), 0)

        # Check if the total count matches the number of lines in the file
        total_count = sum(tag_counts.values())
        with open(self.dummy_logs_path, 'r') as f:
            line_count = sum(1 for _ in f)
        self.assertEqual(total_count, line_count)


if __name__ == '__main__':
    unittest.main()