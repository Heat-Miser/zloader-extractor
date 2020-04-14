# zloader-extractor
A script to extract network IOCs from Zloader xls droppers

### Prerequisites
#### Requirements

```
$>pip install -r requirements.txt
```


## Usage

One one file:

```
$>python3 zloader_pown.py -f <xls file>
```

Recursively on a directory (every file will be matched against the embedded yara rule):

```
$>python3 zloader_pown.py -d <path to the directory>
```