unit U_Connect;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs, StdCtrls, ExtCtrls,U_Functions_type, Buttons;

type
  TConnectForm1 = class(TForm)
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    LabeledEdit1: TLabeledEdit;
    LabeledEdit2: TLabeledEdit;
    LabeledEdit3: TLabeledEdit;
    BitBtn1: TBitBtn;
    LabeledEdit4: TLabeledEdit;
    LabeledEdit5: TLabeledEdit;
    procedure BitBtn1Click(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  ConnectForm1: TConnectForm1;

implementation
Uses U_Maneger;
{$R *.dfm}

procedure TConnectForm1.BitBtn1Click(Sender: TObject);
begin
  if LabeledEdit1.Text = '' then exit;
  if LabeledEdit2.Text = '' then exit;
  if LabeledEdit3.Text = '' then exit;
  if LabeledEdit4.Text = '' then exit;
  if LabeledEdit5.Text = '' then exit;
  with ConnectParams do
  begin
    INHOST := LabeledEdit1.Text;
    INPORT := StrToInt(LabeledEdit4.Text);
    INUSER := LabeledEdit2.Text;
    INPWD := LabeledEdit3.Text;
    InBDName := LabeledEdit5.Text;
  end;
  ConnectForm1.Hide;
  U_Maneger.Form1.Show;
end;

end.
