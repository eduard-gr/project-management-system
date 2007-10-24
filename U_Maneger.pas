unit U_Maneger;

interface

uses
  Windows, Messages, SysUtils, Variants, Classes, Graphics, Controls, Forms,
  Dialogs,U_Functions_type, DB, mySQLDbTables, ExtCtrls, StdCtrls, ComCtrls,
  Menus, DBClient, Provider, Grids, ValEdit, DBGrids, DBCtrls, Buttons,uMysqlClient;

type
  TForm1 = class(TForm)
    Panel1: TPanel;
    Splitter1: TSplitter;
    Panel2: TPanel;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    TabControl1: TTabControl;
    PopupMenu1: TPopupMenu;
    PageControl1: TPageControl;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;
    DBGrid1: TDBGrid;
    ValueListEditor1: TValueListEditor;
    DataSetProvider1: TDataSetProvider;
    ClientDataSet1: TClientDataSet;
    DataSource1: TDataSource;
    DBMemo1: TDBMemo;
    Memo1: TMemo;
    BitBtn1: TBitBtn;
    BitBtn2: TBitBtn;
    BitBtn3: TBitBtn;
    procedure FormActivate(Sender: TObject);
    procedure PageControl1Change(Sender: TObject);
    procedure BitBtn1Click(Sender: TObject);
    procedure FormClose(Sender: TObject; var Action: TCloseAction);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  Form1: TForm1;

implementation
Uses U_Connect;
{$R *.dfm}
procedure TForm1.FormActivate(Sender: TObject);
begin
  with Sql_Connect do
  begin
    Host := ConnectParams.INHOST;
    Port := ConnectParams.INPORT;
    UserName := ConnectParams.INUSER;
    UserPassword := ConnectParams.INPWD;
    DatabaseName  := ConnectParams.InBDName;
   try
     Connected := True;
     //ShowMessage('Connected');
     MySqlQuery1.Active := True;
     ClientDataSet1.Active := True;
     if PageControl1.TabIndex = 0 then
     begin
       DBMemo1.Visible := True;
       Memo1.Visible := false;
     end;
     if PageControl1.TabIndex = 1 then
     begin
       DBMemo1.Visible := False;
       Memo1.Visible := True;
     end;
   except
     ShowMessage('Connect Fatal Error');
   end;
  end;
end;

procedure TForm1.PageControl1Change(Sender: TObject);
begin
  if PageControl1.TabIndex = 0 then
  begin
    DBMemo1.Visible := True;
    Memo1.Visible := false;
  end;

  if PageControl1.TabIndex = 1 then
  begin
    DBMemo1.Visible := False;
    Memo1.Visible := True;
  end;
end;

procedure TForm1.BitBtn1Click(Sender: TObject);
begin
//try
MySqlQuery2.Active := true;
//except
//Showmessage('Error');
//end;
end;

procedure TForm1.FormClose(Sender: TObject; var Action: TCloseAction);
begin
Sql_connect.Connected := false;
U_Connect.ConnectForm1.Close;
end;

end.
