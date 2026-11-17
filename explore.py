import gzip, json, glob

files = sorted(glob.glob("data/AWSLogs/**/*.json.gz", recursive=True))
print(len(files), "files")

with gzip.open(files[0], "rt") as f:
    data = json.load(f)

print(len(data["Records"]), "records in the first file")
print(json.dumps(data["Records"][0], indent=2))