# -*- coding: utf-8 -*-
# Idempotent patcher: adds a Windows-safe serial loader to AppCompatProcessor and
# routes the load dispatcher to it on Windows (os.name == 'nt'). Run with python2.
import io, os, py_compile

ACP = r"C:\DFIR\tools\appcompatprocessor"
appload = os.path.join(ACP, "appLoad.py")
mainpy = os.path.join(ACP, "AppCompatProcessor.py")

SERIAL_SRC = '''

def appLoadSerial(pathToLoad, dbfilenameFullPath, maxCores, governorOffFlag):
    # Windows-safe SERIAL loader. The stock loader (appLoadMP) drives a fork-based
    # producer/consumer engine (mpEngineProdCons) that deadlocks under Windows 'spawn'
    # multiprocessing -- which is why upstream disabled Windows support. This routine
    # performs the identical ingest (same Task.processFile parse + same Entries/FilePaths
    # insert as appLoadCons.do_work) inline in a single process, so ACP runs natively on
    # Windows. Selected automatically when os.name == 'nt'.
    global _tasksPerJob
    t0 = datetime.now()
    logger.debug("Starting appLoadSerial (Windows single-process loader)")
    file_filter = '|'.join([v.getFileNameFilter() for k, v in ingest_plugins.iteritems()])
    file_filter += "|.*\\.zip$"

    if os.path.isdir(pathToLoad) and os.path.basename(pathToLoad).lower() == 'RedlineAudits'.lower():
        files_to_process = searchRedLineAudits(pathToLoad)
    elif os.path.isdir(pathToLoad):
        files_to_process = searchFolders(pathToLoad, file_filter)
    else:
        files_to_process = processArchives(pathToLoad, file_filter)

    if not files_to_process:
        logger.info("Found no files to process!")
        return

    DB = appDB.DBClass(dbfilenameFullPath, True, settings.__version__)
    conn = DB.appConnectDB()

    instancesToProcess = GetIDForHosts(files_to_process, DB)
    countInstancesToProcess = len(instancesToProcess)
    logger.info("Found %d new instances" % countInstancesToProcess)

    if countInstancesToProcess < _tasksPerJob:
        _tasksPerJob = 1

    task_list = [Task(pathToLoad, chunk) for chunk in chunks(instancesToProcess, _tasksPerJob)]
    if not task_list:
        logger.info("Found no files to process!")
        return

    prod = appLoadProd.__new__(appLoadProd)
    prod.logger = logger
    prod.check_killed = lambda: None

    total = len(task_list)
    done = 0
    for task in task_list:
        rowsData = prod.do_work(task)
        if rowsData:
            numFields = len(rowsData[0]._asdict().keys()) - 4
            valuesQuery = "(NULL," + "?," * numFields + "0, 0)"
            try:
                with closing(conn.cursor()) as c:
                    insertList = []
                    for x in rowsData:
                        tmp_file_path = x.FilePath
                        c.execute("INSERT OR IGNORE INTO FilePaths VALUES (NULL, '%s')" % tmp_file_path)
                        x.FilePathID = DB.QueryInt("SELECT FilePathID FROM FilePaths WHERE FilePath = '%s'" % tmp_file_path)
                        insertList.append((x.HostID, x.EntryType, x.RowNumber, x.LastModified, x.LastUpdate, x.FilePathID, x.FileName, x.Size, x.ExecFlag, x.SHA1, x.FileDescription, x.FirstRun, x.Created, x.Modified1, x.Modified2, x.LinkerTS, x.Product, x.Company, x.PE_sizeofimage, x.Version_number, x.Version, x.Language, x.Header_hash, x.PE_checksum, str(x.SwitchBackContext), x.InstanceID))
                    c.executemany("INSERT INTO Entries VALUES " + valuesQuery, insertList)
            except sqlite3.Error as er:
                logger.error("appLoadSerial - Sqlite error: %s" % er.message)
            conn.commit()
        done += 1
        logger.info("appLoadSerial: ingested host instance %d/%d" % (done, total))

    conn.commit()
    conn.close()
    logger.info("Load time: %s" % str(datetime.now() - t0).split(".")[0])
'''

# 1) backups
for f in (appload, mainpy):
    b = f + ".serialbak"
    if not os.path.exists(b):
        io.open(b, "wb").write(io.open(f, "rb").read())

# 2) append serial loader to appLoad.py
s = io.open(appload, "rb").read()
if b"def appLoadSerial" not in s:
    io.open(appload, "ab").write(SERIAL_SRC.encode("ascii"))
    print("appended appLoadSerial to appLoad.py")
else:
    print("appLoadSerial already present in appLoad.py")

# 3) route dispatcher to serial loader on Windows
m = io.open(mainpy, "rb").read()
if b"appLoadSerial" not in m:
    m = m.replace(b"from appLoad import appLoadMP",
                  b"from appLoad import appLoadMP, appLoadSerial")
    m = m.replace(b"appLoadMP(options.pathtoload, dbfilenameFullPath, options.maxCores, options.governorOffFlag)",
                  b"(appLoadSerial if os.name == 'nt' else appLoadMP)(options.pathtoload, dbfilenameFullPath, options.maxCores, options.governorOffFlag)")
    io.open(mainpy, "wb").write(m)
    print("patched dispatcher in AppCompatProcessor.py")
else:
    print("dispatcher already references appLoadSerial")

# 4) syntax check
py_compile.compile(appload, doraise=True)
py_compile.compile(mainpy, doraise=True)
print("COMPILE OK")
