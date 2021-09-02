using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.Security.Principal;
using System.IO;
using System.Linq;

//Author @evilash
namespace SharpEventLog
{
    class Program
    {
        public struct Loginfo
        {
            public string username;
            public string sip;
            public string sid;
            public string domainname;

        };

        static void Main(string[] args)
        {
            
            if (args.Length == 0)
            {
                System.Console.WriteLine("");
                System.Console.WriteLine("获取DC登录日志，分析域用户对应机器的IP");
                System.Console.WriteLine("支持 1-365 天日志提取");
                System.Console.WriteLine("@evilash\n");
                System.Console.WriteLine("ex: .\\SharpADUserIP.exe 7  //获取7天日志分析");

            }

            if (args.Length == 1 )
            {
                int days = int.Parse(args[0]);

                if (days > 1 && days < 365)
                {
                    Get4624Log(days);
                }
               
            }
                
        }

        public static void Get4624Log(int days)
        {
            EventLog log = new EventLog("Security");
            
            var entries = log.Entries.Cast<EventLogEntry>().Where(x => (x.InstanceId == 4624 && x.TimeGenerated >= DateTime.Now.AddDays(0 - days)));
            //x.TimeGenerated >= DateTime.Now.AddDays(-30)

            entries.Select(x => new { x.ReplacementStrings }).ToList();

            //entries.ReplacementStrings[4] SID
            //entries.ReplacementStrings[18] 源IP

            List<Loginfo> listinfo = new List<Loginfo>();
            Loginfo info = new Loginfo();
            int Validnum = 0;
            foreach (EventLogEntry inlog in entries)
            {
                string sid = inlog.ReplacementStrings[4];
                string username = inlog.ReplacementStrings[5];
                string sip = inlog.ReplacementStrings[18];
                string domainname = inlog.ReplacementStrings[6];

                if (sid.Length > 12 && (!username.Contains("$")) && (sip.Length > 1))
                {
                    if (listinfo.Exists(x => (x.sid == inlog.ReplacementStrings[4]) && (x.sip == inlog.ReplacementStrings[18])) == false)
                    {
                        info.sid = sid;
                        info.username = username;
                        info.sip = sip;
                        info.domainname = domainname;

                        listinfo.Add(info);
                        Validnum++;
                    }

                }

            }

            //listinfo.Where((x, i) => listinfo.FindIndex(z => (z.sid == x.sid) && (z.sip == x.sip)) == i);


            for (int i = 0; i < Validnum; i++)
            {
                Console.WriteLine("Sid: " + listinfo[i].sid);
                Console.WriteLine("用户名: " + listinfo[i].domainname + "\\" + listinfo[i].username);
                Console.WriteLine("源IP: " + listinfo[i].sip );
                Console.WriteLine("-------------------------------------------\n");

            }
            Console.WriteLine("用户有效登录日志条数：" + Validnum);

        }

        //Convert Sid to Username
        public static string SidtoUserName(string Sid)
        {
            string result = string.Empty;
            SecurityIdentifier ConvertSid = new System.Security.Principal.SecurityIdentifier(Sid);
            var ntAccount = (NTAccount)ConvertSid.Translate(typeof(NTAccount));
            result = ntAccount.ToString();
            return result;
        }

    }
}
