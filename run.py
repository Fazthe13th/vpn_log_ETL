from parseLog import ParseLog
import time


def follow(thefile):
    readLog = ParseLog()
    thefile.seek(0, 2)  # Go to the end of the file
    while True:
        line = thefile.readline()
        if not line:
            time.sleep(0.1)  # Sleep briefly
            continue
        readLog.read_lines(str(line).strip())


if __name__ == "__main__":
    filename = 'log_file_location'
    file_open = open(filename, 'r')
    follow(file_open)
