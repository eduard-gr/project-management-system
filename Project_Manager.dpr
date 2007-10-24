program Project_Manager;

uses
  Forms,
  U_Connect in 'U_Connect.pas' {ConnectForm1};

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TConnectForm1, ConnectForm1);
  Application.Run;
end.
