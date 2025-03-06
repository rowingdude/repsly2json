# Repsly JSON Export Utility

A high-performance data export utility for the Repsly API that retrieves and converts Repsly data to JSON format for further processing or archiving.

## Features

- Exports data from all available Repsly API endpoints
- Supports both complete and incremental data exports
- Implements intelligent pagination with adaptive rate limiting
- Automatically handles API limitations and error recovery
- Provides detailed progress reporting and logging
- Special handling for Visit Realizations with date-based pagination
- Robust error handling and retry mechanisms
- Command-line configuration options

## Usage

### Options

- `--no-pagination`: Retrieve only the first page of data from each endpoint
- `--incremental`: Fetch only new data since the last run
- `--config=PATH`: Specify a custom configuration file path
- `--log-level=LEVEL`: Set logging level (DEBUG, INFO, WARNING, ERROR)

## Requirements

- libcurl for HTTP requests
- jsoncpp for JSON parsing and generation
- C++17 compatible compiler

This utility is our "step 1" of getting data correctly out of Repsly to be uploaded to the database. We have built a robust pagination system that accounts for all of Repsly's ... various ... data definitions. On its own, my utility is designed for efficient handling of large data sets while respecting API rate limits and maintaining data integrity. It's particularly useful for regular data backups or integrating Repsly data with other systems. 


