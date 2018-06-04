# Smart Url Fuzzer
An asynchronous, robust website URLs explorer.<br>
Discovers websites resources.<br>
Highly configurable yet fast and simple.<br>
I developed this for pentesting purposes,<br>
Companies provide this service for money, so I decided to do it on my own.<br>
<b>Please use it responsibly.<b>

### Examples

```bash
# This will find all the active endpoints in https://www.example.com
$ python fuzz.py 
```

### Custom words lists
```bash
$ python fuzz.py --help
Usage: fuzz.py -u https://example.com/

An Asynchronous, robust websites endpoint discovery tool with smart error
handling. Locates resources in websites based on a list of paths. Check out
the "words_list"" directory for lists examples.

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -u BASE_URL, --url=BASE_URL
                        The target website to scan.
  -l LIST_FILE, --list=LIST_FILE
                        A file containing the paths to check (separated with
                        lines).
```

You can use a custom paths lists, based on the website type, or based on your needs.<br>
The directory 'words_lists' contains a some lists of the most common endpoints.  

```bash
$ python fuzz.py -u https://www.facebook.com -l words_lists/list-php.txt
####-##-## ##:##:##,### - fuzzing - INFO - Getting the endpoints of the website https://www.facebook.com with list file "words_lists/list-php.txt" and 100 async workers.
# ...
https://www.facebook.com/comment_edit.php : 200
https://www.facebook.com/webdb_view_test.php : 200
https://www.facebook.com/sp_feedgenerator.php : 200
https://www.facebook.com/xp_publish.php : 200
https://www.facebook.com/categories_0222.php : 200
https://www.facebook.com/3d_exhibits1.php : 200
https://www.facebook.com/adr_cell.php : 200
####-##-## ##:##:##,### - fuzzing - INFO - The endpoints were exported to "endpoints.txt"

```

### Workers
If the fuzzing failed for any http reason, it continues with less workers automatically.<br>
Some sites have DDOS protection mechanisms.<br>
The fuzzer will reach the optimal number of workers automatically, without getting blocked.<br>

### Logs
All the activity is logged under /logs folder by default.<br>