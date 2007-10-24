object ConnectForm1: TConnectForm1
  Left = 391
  Top = 217
  BorderStyle = bsToolWindow
  Caption = 'Project Manager [Connect Params]'
  ClientHeight = 176
  ClientWidth = 415
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -11
  Font.Name = 'MS Sans Serif'
  Font.Style = []
  OldCreateOrder = False
  PixelsPerInch = 96
  TextHeight = 13
  object GroupBox1: TGroupBox
    Left = 159
    Top = 0
    Width = 256
    Height = 176
    Align = alClient
    TabOrder = 0
    object LabeledEdit1: TLabeledEdit
      Left = 16
      Top = 24
      Width = 169
      Height = 21
      EditLabel.Width = 71
      EditLabel.Height = 13
      EditLabel.Caption = 'Remout Server'
      TabOrder = 0
      Text = '83.99.142.228'
    end
    object LabeledEdit2: TLabeledEdit
      Left = 16
      Top = 64
      Width = 137
      Height = 21
      EditLabel.Width = 22
      EditLabel.Height = 13
      EditLabel.Caption = 'User'
      TabOrder = 1
      Text = 'root'
    end
    object LabeledEdit3: TLabeledEdit
      Left = 16
      Top = 104
      Width = 137
      Height = 21
      EditLabel.Width = 46
      EditLabel.Height = 13
      EditLabel.Caption = 'Password'
      PasswordChar = '*'
      TabOrder = 2
      Text = 'imbionikuspokus'
    end
    object BitBtn1: TBitBtn
      Left = 168
      Top = 144
      Width = 81
      Height = 25
      Caption = 'Connect'
      TabOrder = 3
      OnClick = BitBtn1Click
      Glyph.Data = {
        56020000424D5602000000000000560100002800000010000000100000000100
        08000000000000010000120B0000120B0000480000004800000000000000FFFF
        FF00605F650068606900FF00FF00747074006D686A0072646900BAB7B800847B
        7D0064585A00807576006763630037363600811E0000501300004A444100C051
        0300773202006E645D00826F5F00AA998700CAA07000413B3300433D3500FF9D
        1100F79E2400FFA72600FFA92800FF9D0800FFA71D00FFAB2500FFAC2700FFB8
        4400EFB75F00443C2F00CBB49100EAAD4200413B3100EBB74E00B49E7200FFCC
        5A00EBBA5400FECA4F00FFD77300FFD77500FFD45900EDC96B00FEDA7E00E1CC
        9000FFDA6C008B7F5900D8C98C00FFED9200BAB18600FFEE8B00FFF8A600C9C6
        990031323200BCF2FF00BDF2FF0065DEFF0066DDFF001ECAFF0000BDFF00004B
        82002F3237006062660067686E00353640004B4B4B002D2D2D00040404040447
        47474704040404040404040404044708050C0B47040404040404040404044743
        070A0D0404040404040404040446241509034545040404040404040404461D20
        212216143A040404040404040446191B1C1F1E1A230404040404040404462B2C
        302D2925260404040404040404462E3738353227170404040404040404462836
        39342F2A18040404040404040404421002440613040404040404040404040412
        330F0404040404040404040404044141414141040404040404040E0E0E0E413E
        3F40410F0E0E0E0E0E0E31313131413C3E3F4133313131313131111111114101
        3B3D411211111111111104040404414141414104040404040404}
    end
    object LabeledEdit4: TLabeledEdit
      Left = 192
      Top = 24
      Width = 57
      Height = 21
      EditLabel.Width = 19
      EditLabel.Height = 13
      EditLabel.Caption = 'Port'
      TabOrder = 4
      Text = '3306'
    end
    object LabeledEdit5: TLabeledEdit
      Left = 16
      Top = 144
      Width = 137
      Height = 21
      EditLabel.Width = 81
      EditLabel.Height = 13
      EditLabel.Caption = 'Data Base Name'
      TabOrder = 5
      Text = 'ttest'
    end
  end
  object GroupBox2: TGroupBox
    Left = 0
    Top = 0
    Width = 159
    Height = 176
    Align = alLeft
    TabOrder = 1
  end
end
