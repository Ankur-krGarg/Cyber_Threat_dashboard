# src/parse_threat_data.py

from pathlib import Path
import pandas as pd
import logging

from parser_logic import parse_json, parse_xml, parse_txt

# Paths
DATA_DIR = Path(__file__).resolve().parent.parent / "data"
PROCESSED_DIR = Path(__file__).resolve().parent.parent / "processed"
PROCESSED_DIR.mkdir(exist_ok=True)

logging.basicConfig(
    filename='parser.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def main():
    all_records = []

    for file in DATA_DIR.iterdir():
        if file.suffix == ".json":
            all_records.extend(parse_json(file))
        elif file.suffix == ".xml":
            all_records.extend(parse_xml(file))
        elif file.suffix == ".txt":
            all_records.extend(parse_txt(file))
        else:
            logging.warning(f"Unsupported format: {file.name}")

    if not all_records:
        logging.error("No data parsed. Exiting.")
        return

    df = pd.DataFrame(all_records)

    df.to_csv(PROCESSED_DIR / "threats.csv", index=False)
    df.to_json(PROCESSED_DIR / "threats.json", orient="records", indent=2)

    print(f"✅ Parsed and saved {len(df)} records to /processed/")


if __name__ == "__main__":
    main()
