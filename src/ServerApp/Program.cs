﻿using System;
using System.IO;
using log4net;
using log4net.Config;
using ServerApp.Shared;

namespace ServerApp
{
    public static class Program
    {
        private static readonly ILog Log = LogManager.GetLogger("ServerApp");

        public static int Main()
        {
            try
            {
                XmlConfigurator.Configure(new FileInfo("log4net.config"));

                ServerHelper.StartServer();

                Log.Info("Press enter for exit");
                Console.Read();

                Log.Info("Exiting ...");

                return 0;
            }
            catch (Exception e)
            {
                Log.Error("ServerApp has failed", e);

                return e.HResult;
            }
        }
    }
}
