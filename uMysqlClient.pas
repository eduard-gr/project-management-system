{--------------------------------------------------------------------------------
Licencing issues:
05-January-2002      ©Cristian Nicola
Note:
 Mysql is copyright by MySQL AB. Refer to their site ( http://www.mysql.com )
for licencing issues.
 Zlib is copyright by Jean-loup Gailly and Mark Adler. Refer to their site for
licencing issues. ( http://www.info-zip.org/pub/infozip/zlib/ )

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

NOTES:
  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. If you are using it for a commercial software it must be open source and
     it must include full source code of this library in an unaltered fashion
     or you would need to ask for permission to use it. This library will be
     considered donationware which means if you want to contribute with any money
     or hardware you are more than welcome.
  4. This notice may not be removed or altered from any source distribution.

  Cristian Nicola
  n_cristian@hotmail.com

If you use the mysqldirect library in a product, i would appreciate *not*
receiving lengthy legal documents to sign. The sources are provided
for free but without warranty of any kind.  The library has been
entirely written by Cristian Nicola after libmysql of MYSQL AB.
--------------------------------------------------------------------------------}
unit uMysqlClient;
////////////////////////////////////////////////////////////////////////////////
// This is the main unit and it defines:
// - mysql client for communication stuff
// - mysql result for dealing with the results of queryes

interface

{$I mysqlinc.inc}

uses
    classes, sysutils, uMysqlCT, uMysqlErrors, uMysqlNet {$IFDEF HAVE_SSL}, uMysqlSSL {$ENDIF};

type
    PCardinal = ^Cardinal;

    TMysql_Row = ^pchar;
    // double linked list to store a result set
    // in libmysql it was single linked
    PMysql_Rows = ^TMysql_Rows;
    TMysql_Rows = record
      prior: PMysql_Rows;
      next: PMysql_Rows;
      data: TMysql_Row;
    end;

    //internal structure to use when reading a result
    TMYSQL_DATA = record
      rows:comp;
      fields:longint;
      data: PMysql_Rows;
    end;
    PMYSQL_DATA = ^TMYSQL_DATA;

//------------------------------------------------------------------------------
    PMysql_FieldDef = ^TMysql_FieldDef;
    TMysql_FieldDef = record
      Name       : pchar;
      Table      : pchar;
      //Def        : pchar; //it was only used on list fields
      FieldType  : byte;
      Length     : cardinal;
      Max_Length : cardinal;
      Flags      : cardinal;
      Decimals   : cardinal;
    end;
    TResultType=(rtUsed,rtStored);

//==============================================================================
  TMyField = class(TObject)
    private
      value : Pchar;
      function GetInteger: Integer;
      function GetString : String;
      function GetBool : Boolean;
      function GetDateTime : TDateTime;
      function GetFloat: Real;
    public
      property AsString : String read GetString;
      property AsInteger : Integer read GetInteger;
      property AsBool : Boolean read GetBool;
      property AsDateTime : TDateTime read GetDateTime;
      property AsFloat : Real read GetFloat;
  end;

    TMysqlClient = class;
    TMysqlResult = class(TObject)
      private
        ffieldscount   : longint;
        frowscount     : comp;
        ffields        : PMysql_FieldDef;
        fhandle        : TMysqlClient;
        fType          : TResultType;
        flengths       : PCardinal;
        frow           : TMysql_Row;
        fdata          : PMysql_Data;
        fdata_cursor   : PMysql_Rows;
        fRecNo         : comp;
        fcurrent_row   : TMysql_Row;
        fEOF           : boolean;
        fBOF           : boolean;
        flengthsread   : boolean;
        fLastRow       : longint;
        fMyField       : TMyField;

        //procedure SetBOF(const Value: boolean);
        //procedure SetEOF(const Value: boolean);
        procedure SetRecNo(const Value: comp);
        procedure SetHasLengths(const Value: boolean);
        function GetHadErrors: boolean;
        function GetLastRowRead: boolean;

      public
        property EOF:boolean read fEof {write SetEOF};
        property BOF:boolean read fBof {write SetBOF};
        property RecNo: comp read fRecNo write SetRecNo;
        property HasLengths:boolean read flengthsread write SetHasLengths;

        property FieldsCount:longint read ffieldscount;
        property RowsCount:comp read frowscount;
        property ResultType : TResultType read fType;
        property FieldsDefs : PMysql_FieldDef read ffields;
        property Lengths : PCardinal read flengths;
        property CurrentRow : TMysql_Row read fcurrent_row;

        property HadErrors : boolean read GetHadErrors;
        property LastRowRead : boolean read GetLastRowRead;

        constructor create(aMysql:TMysqlClient; aType:TResultType);
        destructor destroy;override;

        function FieldLength(aIndex:longint):cardinal;
        function FieldValue(aIndex:longint):pchar;
        function FieldDef(aIndex:longint):PMysql_FieldDef;

        function FieldValueByName (aName:string; CaseSensitive:boolean):pchar;

        // begin tam
        function FieldByName(aName : string) : TMyField;
        function FieldByIndex(aIndex : LongInt) : TMyField;
        // end tam

        function FieldDefByName (aName:string; CaseSensitive:boolean):PMysql_FieldDef;
        function FieldIndexByName(aName:string; CaseSensitive:boolean):longint;

        procedure Next;
        procedure Prior;
        procedure First;
        procedure Last;
        procedure FetchLengths;
end;

//==============================================================================
    TMysqlClient = class (TObject)
      private
        fnet                 : TMysqlNet; //internal net
        fhost                : string; //internal host
        fuser                : string; //internal user
        fpasswd              : string; //internal password
        funix_socket         : string; //internal unix socket
        fdb                  : string; //internal db
        fport                : cardinal; //internal port
        fscramble_buff       : string[9]; //internal scramble buffer (used for password encryption)
        fthread_id           : cardinal; //internal thread id for current connection
        faffected_rows       : comp; //internal affected rows
        finsert_id           : comp; //last insert id
        fstatus              : TMysql_Status;//status of the client
        freconnect           : boolean;//internal reconnect flag if true one should reconnect
        fnamed_pipe          : Boolean;//do we use named pipes?
        ftrysock             : boolean;//if we use named pipes should we attempt sockets if pipe is down?
        fconnect_timeout     : cardinal;//time out on connect
        fcompress            : Boolean; //if we use compressed protocol
        fclient_flag         : cardinal;

        fserver_version      : string;
        fserver_capabilities : cardinal;
        fserver_status       : longint;
        fserver_language     : cardinal;
        fextra_info          : comp;
        finfo                : string;

        ffield_count         : longint;
        ffields              : PMysql_FieldDef;

        fusedresult          :TMysqlResult;
        fuse_ssl             : Boolean;
        {$IFDEF HAVE_SSL}
        fssl_key         : string;
        fssl_cert        : string;
        fssl_ca          : string;
        fssl_capath      : string;
        fssl_cipher      : string;
        {$ENDIF}
        FSQL             : TStringList;

        function send_file_to_server(const filename:string):longint;
        function read_rows(mysql_fields:PMysql_FieldDef;fields:longint; var hadErrors:boolean):PMYSQL_DATA;
        function read_one_row(fields:longint;row:TMysql_Row;lengths:PCardinal):longint;
        function simple_command(command:TEnumServerCommand; arg:string;lengt:longint; skipp_check:boolean; retry:boolean):longint;
        function read_query_result:longint;
        procedure free_old_query;
        function unpack_fields(data:PMYSQL_DATA;fields:longint;long_flag_protocol:boolean):PMysql_FieldDef;
        function store_result:TMysqlResult;
        function use_result:TMysqlResult;

        procedure SetHost(const Value: string);
        procedure SetDb(const Value: string);
        procedure SetPasswd(const Value: string);
        procedure SetPort(const Value: cardinal);
        procedure SetUnixSocket(const Value: string);
        procedure SetUser(const Value: string);
        procedure SetClientFlag(const Value: cardinal);
        procedure SetNamedPipe(const Value: Boolean);
        procedure SetTrySock(const Value: Boolean);
        procedure setfcompress(const Value: Boolean);
        procedure SetUseSSL(const Value: Boolean);
        {$IFDEF HAVE_SSL}
        procedure Setsslca(const Value: string);
        procedure Setsslcapath(const Value: string);
        procedure Setsslcert(const Value: string);
        procedure Setsslcipher(const Value: string);
        procedure Setsslkey(const Value: string);
        {$ENDIF}

        function GetLastErrorNo: cardinal;
        function GetLastError: string;
        function GetClientInfo: string;
        function GetProtocol_version: cardinal;
        function GetConnected: boolean;

      public
        property Host: string read FHost write SetHost;
        property User: string read FUser write SetUser;
        property Password:string read FPasswd write SetPasswd;
        property UnixSocket: string read funix_socket write SetUnixSocket;
        property Db: string read fdb write SetDb;
        property Port: cardinal read FPort write SetPort;
        property ClientFlag: cardinal read fclient_flag write SetClientFlag;

        property ShouldReconnect: boolean read freconnect write freconnect;
        property UseNamedPipe: Boolean read fnamed_pipe write SetNamedPipe;
        property TrySockets: Boolean read ftrysock write SetTrySock;
        property ConnectTimeout: cardinal read fconnect_timeout write fconnect_timeout;
        property Compress: Boolean read fcompress write setfcompress;

        property Status: TMysql_Status read fstatus;
        property ThreadId: cardinal read fthread_id;
        property AffectedRows: comp read faffected_rows;
        property LastInsertId: comp read finsert_id;

        property ServerVersion: string read fserver_version;
        property ClientVersion: string read GetClientInfo;
        property ProtocolVersion: cardinal read GetProtocol_Version;

        property ServerCapabilities: cardinal read fserver_capabilities;
        property ServerStatus: longint read fserver_status;
        property ServerLanguage: cardinal read fserver_language;
        property ExtraInfo: comp read fextra_info;
        property Info: string read finfo;
        property Connected: boolean read GetConnected;

        property LastError: string read GetLastError;
        property LastErrorNo: cardinal read GetLastErrorNo;

        property UseSSL : Boolean read fuse_ssl write SetUseSSL;
        {$IFDEF HAVE_SSL}
        property SSLKey : string read fssl_key write Setsslkey;
        property SSLCert : string read fssl_cert write Setsslcert;
        property SSLCa : string read fssl_ca write Setsslca;
        property SSLCaPath : string read fssl_capath write Setsslcapath;
        property SSLCipher : string read fssl_cipher write Setsslcipher;
        {$ENDIF}
        property Sql : TStringList read fsql write fsql;

        constructor create;
        destructor destroy; override;

        function connect(ahost:string; auser:string ; apasswd:string ; adb:string; aport:cardinal; aunix_socket:string; atrysocket:boolean ; aclient_flag:longint ):boolean;
        function connect1:boolean;
        function reconnect:boolean;
        procedure close;

        function select_db( const newdb:string):boolean;
        function create_db(const adb:string):boolean;
        function drop_db(const adb:string):boolean;

        function change_user(NewUser:string; NewPasswd:string; NewDb: string):boolean;
        function refresh(options:longint):boolean;
        function dump_debug_info:boolean;
        function kill(pid:longint):boolean;
        function ping:boolean;
        function shutdown:boolean;

        function query( const aquery:string; StoreResult:boolean;var ExecutedOk:boolean):TMysqlResult;
        function query1( StoreResult:boolean;var ExecutedOk:boolean):TMysqlResult;
        function Exec : TMysqlResult;

        function stat:string;
        function list_processes:TMysqlResult;
        {$IFDEF HAVE_SSL}
        function SSL_ReadError:boolean;
        {$ENDIF}
  end;

implementation

type
    //internal array of pchar
    TPPCA=array [0..maxint div 4] of pchar;
    //internal array of cardinal
    TPCA=array [0.. maxint div 4] of cardinal;
    //internal array of field def
    TPFDA=array [0.. maxint div sizeof(TMysql_FieldDef)] of TMysql_FieldDef;

////////////////////////////////////////////////////////////////////////////////
// free for a PMysql_Data structure
procedure free_rows(var cur: PMYSQL_DATA);
var row,tmp:PMysql_Rows;
    i:longint;
begin
     if (cur<>nil) then //is it empty?
     begin
          row:=cur^.data;
          while row<>nil do
          begin
               for i:=0 to cur^.fields-1 do //let's free the fields
                   strdispose(TPPCA(row^.data^)[i]);
               dispose(row^.data);
               tmp:=row;
               row:=row^.next;
               dispose(tmp); //we can free the row
          end;
          dispose(cur); //finally we can free the PMysql_Data
          cur:=nil;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// length decoder
// refer mysql docs to see why 251,252,253
function net_field_length(var packet: Integer): longint;
begin
     if ( pchar(packet)[0] < chr(251)) then //1 byte value
     begin
          result:= byte(pchar(packet)[0]);
          inc(packet);
          exit;
     end;
     if ( pchar(packet)[0] = chr(251)) then //null length
     begin
          inc(packet);
          result:=NULL_LENGTH;
          exit;
     end;
     if ( pchar(packet)[0] = chr(252)) then //2 bytes value
     begin
          result:=byte(pchar(packet)[1])+ (byte(pchar(packet)[2]) shl 8);
          packet:=packet+3;
          exit;
     end;
     if ( pchar(packet)[0] = chr(253)) then //3 bytes value
     begin
          result:= byte(pchar(packet)[1])+ (byte(pchar(packet)[2]) shl 8)+(byte(pchar(packet)[3]) shl 16);
          packet:=packet+4;
          exit
     end;
     //4 bytes value
     result:= byte(pchar(packet)[1])+ (byte(pchar(packet)[2]) shl 8)+ (byte(pchar(packet)[3]) shl 16)+ (byte(pchar(packet)[4]) shl 24);
     packet:=packet+9;
end;

////////////////////////////////////////////////////////////////////////////////
// length decoder this one returns int64 values
// refer mysql docs to see why 251,252,253
function net_field_length_ll(var packet: Integer): comp;
var a:comp;
begin
     if ( pchar(packet)[0] < chr(251)) then //1 byte value
     begin
          result:= (byte(pchar(packet)[0]));
          inc(packet);
          exit;
     end;
     if ( pchar(packet)[0] = chr(251)) then //Null length
     begin
          inc(packet);
          result:=NULL_LENGTH;
          exit;
     end;
     if ( pchar(packet)[0] = chr(252)) then //2 bytes value
     begin
          result:=byte(pchar(packet)[1])+ (byte(pchar(packet)[2]) shl 8);
          packet:=packet+3;
          exit;
     end;
     if ( pchar(packet)[0] = chr(253)) then //3 bytes value
     begin
          result:= byte(pchar(packet)[1])+ (byte(pchar(packet)[2]) shl 8)+(byte(pchar(packet)[3]) shl 16);
          packet:=packet+4;
          exit
     end;
     packet:=packet+9; //8 bytes value
     result:= (byte(pchar(packet)[1]))+
              (byte(pchar(packet)[2]) shl 8)+
              (byte(pchar(packet)[3]) shl 16)+
              (byte(pchar(packet)[4]) shl 24);
     a:= (byte(pchar(packet)[5]))+
         (byte(pchar(packet)[6]) shl 8)+
         (byte(pchar(packet)[7]) shl 16)+
         (byte(pchar(packet)[8]) shl 24);
     result:=a+result *$FFFF;
end;

////////////////////////////////////////////////////////////////////////////////
// added to not import the entyre math unit
function Floor(X: Extended): longint;
begin
  Result := Trunc(X);
  if (X < 0) and (Result<>X) then
    Result:=Result-1;
end;

////////////////////////////////////////////////////////////////////////////////
type TDQuad=record
        q1:word;
        q2:word;
        end;

////////////////////////////////////////////////////////////////////////////////
function _and(nr1:comp;nr2:comp):comp;
begin
     TDQuad(pointer(@result)^).q1:=TDQuad(pointer(@nr1)^).q1 and TDQuad(pointer(@nr2)^).q1;
     TDQuad(pointer(@result)^).q2:=TDQuad(pointer(@nr1)^).q2 and TDQuad(pointer(@nr2)^).q2;
end;

////////////////////////////////////////////////////////////////////////////////
function _xor(nr1:comp;nr2:comp):comp;
begin
     TDQuad(pointer(@result)^).q1:=(TDQuad(pointer(@nr1)^).q1) xor (TDQuad(pointer(@nr2)^).q1);
     TDQuad(pointer(@result)^).q2:=(TDQuad(pointer(@nr1)^).q2) xor (TDQuad(pointer(@nr2)^).q2);
end;

////////////////////////////////////////////////////////////////////////////////
function _mod(nr1:comp;nr2:comp):comp;
begin
     while nr1>nr2 do
           nr1:=nr1-nr2;
     result:=nr1;
end;

function _shl8(nr1:comp):comp;
var i:longint;
begin
     i:=TDQuad(pointer(@nr1)^).q1 and $FF00;
     TDQuad(pointer(@nr1)^).q1:=TDQuad(pointer(@nr1)^).q1 shl 8;
     TDQuad(pointer(@nr1)^).q2:=TDQuad(pointer(@nr1)^).q2 shl 8;
     TDQuad(pointer(@nr1)^).q2:=TDQuad(pointer(@nr1)^).q2 or (i shr 8);
     result:=_and(nr1,$7fffffff);
end;


////////////////////////////////////////////////////////////////////////////////
// calculates the hash of a pchar (used for password)
procedure hashPassword(pass:pchar; var res0,res1:longint);
var nr,add,nr2,tmp:comp;
    i:longint;
    e1:comp;
    len:longint;
    a:comp;
begin
     nr:=1345345333;
     add:=7;
     nr2:=$12345671;
     len:=strlen(pass)-1;
     for i:=0 to len do
     begin
          if (Pass[i] = #20) or (Pass[i] = #9)then
             continue;
          tmp := $ff AND byte(Pass[i]);
          e1:=(((_and(nr,63) +add)*tmp)+(_shl8(nr)));
          nr:=_xor(nr,e1);
          nr2:=nr2+(_xor(_shl8(nr2),nr));
          add :=add+tmp;
     end;
//     res0 :=TDQuad(pointer(@nr)^).q2;//(_and(nr,$7fffffff));
//     res1 :=TDQuad(pointer(@nr2)^).q2;//(_and(nr2,$7fffffff));
a:=_and(nr,$7fffffff);
     res0 :=longint(pointer(@a)^);//(_and(nr,$7fffffff));
a:=_and(nr2,$7fffffff);
     res1 :=longint(pointer(@a)^);//(_and(nr2,$7fffffff));
end;

////////////////////////////////////////////////////////////////////////////////
// encryption of password
function mysql_scramble( pass:pchar; hashseed:pchar):pchar;
var hp0,hp1:longint;
    hm0,hm1:longint;
    maxValue,seed, seed2 :comp;
    dRes: double;
    i:longint;
    e:byte;
    len:longint;
begin
    if(pass = nil) or (hashseed=nil)then
    begin
         result:=nil;
         exit;
    end;
    len:=strlen(hashseed)-1;
    result:=stralloc(len);

    hashPassword(pass,hp0,hp1);
    hashPassword(hashSeed,hm0,hm1);

//    writeln(format('%d %d %d %d',[hp0,hp1,hm0,hm1]));

    maxValue:= $3FFFFFFF;
    seed  := _mod(( hp0 xor hm0 ),maxValue) ;
    seed2 := _mod(( hp1 xor hm1 ),maxValue) ;

    for i:=0 to len do
    begin
         seed  := _mod(( seed * 3 + seed2  ),maxValue) ;
         seed2 := _mod(( seed + seed2 + 33 ),maxValue) ;
         dRes := Seed / maxValue;
         result[i] := char( floor( dRes * 31 ) + 64 );
    end;
//    writeln('result ', seed);

    seed  := _mod(( seed * 3 + seed2  ),maxValue) ;
    dRes := Seed / maxValue;
    e := floor( dRes * 31 );
    for i := 0 to len do
        result[i] := chr( byte (result[i]) xor e);

    result[len+1]:=#0;
end;

//------------------------------------------------------------------------------
{ TMysqlClient }
//------------------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////
// class constructor
constructor TMysqlClient.create;
begin
     inherited create;
     fnet:=TMysqlNet.create;
     //init internal variables
     fhost:='';
     fuser:='';
     fpasswd:='';
     funix_socket:='';
     fdb:='';
     fport:=3306;
     fscramble_buff:='';
     fusedresult:=nil;
     fthread_id:=0;
     faffected_rows:=0;
     finsert_id:=0;
     fstatus:=MYSQL_STATUS_READY;
     freconnect:=true;
     ftrySock:=false;
     fnamed_pipe:=false;
     fconnect_timeout:=0;
     fcompress:={$IFDEF HAVE_COMPRESS}true;{$ELSE}false{$ENDIF};
     fclient_flag:=CLIENT_CAPABILITIES;
     fserver_version:='';
     fserver_capabilities:=0;
     fserver_status:=SERVER_STATUS_AUTOCOMMIT;
     fserver_language:=0;
     fextra_info:=0;
     finfo:='';
     ffield_count:=0;
     ffields:=nil;
     fuse_ssl:=false;
     fsql:=TStringList.Create;
end;

////////////////////////////////////////////////////////////////////////////////
// class destructor
destructor TMysqlClient.destroy;
begin
     close;
     if assigned(fnet) then
        fnet.free;
     fnet:=nil;
     //may need to free some things
     fsql.free;
     inherited destroy;
end;

////////////////////////////////////////////////////////////////////////////////
// Changes current user to mysql server
// returns true if success
function TMysqlClient.change_user(NewUser: string; NewPasswd: string; NewDb: string): boolean;
var buff:array[0..512] of char;
    i,j:longint;
    somp:pchar;
begin
     fillchar(buff,512,#0);
     //put new user in buffer
     if (NewUser<>'') then
     begin
          i:=length(NewUser);
          if i>32 then //is it longer than 32
             i:=32;
          move(NewUser,pchar(@buff)^,i);
          inc(i);
     end
     else
          i:=1;
     //then the password
     if (NewPasswd<>'') then
     begin
          somp:=mysql_scramble(pchar(@NewPasswd[1]),pchar(@fscramble_buff[1]));
          j:=strlen(somp);
          move(somp[0],pchar(@buff[i])^,j);
          strdispose(somp);
          i:=i+j+1;
     end
     else
          inc(i);
     //if we have a new db
     if (Newdb<>'')then
     begin
          j:=length(Newdb);
          move(Newdb,pchar(@buff[i])^,j);
          i:=i+j+1;
     end
     else
          inc(i);
     //let's try to change user
     if simple_command(COM_CHANGE_USER, strpas(buff),i,false,freconnect)<>0 then
        result:=false //we have an error
     else
     begin //success
          fuser:=NewUser;
          fpasswd:=NewPasswd;
          fdb:= Newdb;
          result:=true; //no errors
     end;
end;

////////////////////////////////////////////////////////////////////////////////
//attempt to create a new db on server
//one may need rights
function TMysqlClient.create_db(const adb: string): boolean;
begin
     result:=simple_command(COM_CREATE_DB,db, length(db),false,freconnect)=0;
end;

////////////////////////////////////////////////////////////////////////////////
// tells to server to drop a db
function TMysqlClient.drop_db(const adb: string): boolean;
begin
     result:=simple_command(COM_DROP_DB,adb,length(adb),false,freconnect)=0;
end;

////////////////////////////////////////////////////////////////////////////////
// tells to server to dump debug details
function TMysqlClient.dump_debug_info: boolean;
begin
     result:=simple_command(COM_DEBUG,'',0,false,freconnect)=0;
end;

////////////////////////////////////////////////////////////////////////////////
// tells to the server to kill a process (must have privileges to do that)
function TMysqlClient.kill(pid: Integer): boolean;
var buff:array[0..3]of char;
begin
     buff[0]:=chr(pid AND $FF);
     buff[1]:=chr((pid shr 8) AND $FF);
     buff[2]:=chr((pid shr 16) AND $FF);
     buff[3]:=chr((pid shr 24) AND $FF);
     result:=simple_command(COM_PROCESS_KILL,buff,4,false,freconnect)=0;
end;

////////////////////////////////////////////////////////////////////////////////
// pings the server to check the connection if still alive
// one may use this after some inactivity to check if the connection is still alive
function TMysqlClient.ping: boolean;
begin
     result:=simple_command(COM_PING,'',0,false,freconnect)=0;
end;

////////////////////////////////////////////////////////////////////////////////
// real connect to server
// returns true if success
function TMysqlClient.connect(ahost:string; auser:string ; apasswd:string ; adb:string ; aport:cardinal ; aunix_socket:string ; atrysocket:boolean ; aclient_flag:longint ):boolean;
var buff:string[NAME_LEN+USERNAME_LENGTH+100];
    curpos:longint;
    i:longint;
    pkt_length:longint;
    somp:pchar;
    {$IFDEF HAVE_SSL}
    apc:pchar;
    {$ENDIF}
begin
     result:=true;
     if not fnet.net_connected then
     begin
     if (ahost='')and(fhost='') then
        begin //no host specified
             result:=false;
             exit;
        end;
     if aHost<>'' then //new host?
        fhost:=ahost;
     fuser:=auser;
     fpasswd:=apasswd;
     fdb:=adb;
     fport:=aport;
     funix_socket:=aunix_socket;
     fclient_flag:=aclient_flag;
     ftrysock:=atrysocket;

     fillchar(buff,NAME_LEN+USERNAME_LENGTH+100,#0);
     //let's try to connect
     if fnamed_pipe then
     begin
          fnet.net_open(VIO_TYPE_NAMEDPIPE,fhost,funix_socket,fport,fconnect_timeout,ftrysock);
          if (fnet.vio_type<>VIO_CLOSED) then
          begin
               if (fnet.vio_type=VIO_TYPE_NAMEDPIPE) then //did we managed to open the pipe?
               begin //set the names
                    if (fhost='') or (fhost<>LOCAL_HOST_NAMEDPIPE) then
                       fhost:=LOCAL_HOST_NAMEDPIPE;
                    if (funix_socket='') or (funix_socket<>MYSQL_NAMEDPIPE) then
                       funix_socket:=MYSQL_NAMEDPIPE;
               end; //if not mark we don't use named pipe
               if (fnet.vio_type<>VIO_TYPE_NAMEDPIPE) then
               begin
                    fnamed_pipe:=false;
                    funix_socket:='';
               end;
          end;
     end
     else
         begin
              fnet.net_open(VIO_TYPE_TCPIP,fhost,funix_socket,fport,fconnect_timeout,true);
              funix_socket:='';
         end;
     //are we connected?
     if fnet.net_connected then
     begin
          if (fconnect_timeout<>0)and(fnet.net_vio_poll_read(fconnect_timeout)) then
          begin //if we don't get anything during time out
               fnet.last_errno:= CR_SERVER_LOST;
               fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
               fnet.net_close;
               result:=false;
               exit;
          end;
          pkt_length:=fnet.net_safe_read;
          if (pkt_length = packet_error) then
          begin //if we got an error
               fnet.net_close;
               result:=false;
               exit;
          end;
          //we have the start packet
          fnet.protocol_version:= byte(pchar(fnet.read_pos)[0]);
          if (fnet.protocol_version <> PROTOCOL_VERSION) and
             (fnet.protocol_version <> PROTOCOL_VERSION-1) then
          begin //do we speak same protocol?
               fnet.last_errno:= CR_VERSION_ERROR;
               fnet.last_error:=format(client_errors[(fnet.last_errno)-CR_MIN_ERROR], [protocol_version,PROTOCOL_VERSION]);
               fnet.net_close;
               result:=false;
               exit;
          end;
          curpos:=1;
          //read server version
          fserver_version:=copy(strpas(pchar(fnet.read_pos+curpos)),1,strlen(pchar(fnet.read_pos+curpos)));
          curpos:=curpos+length(fserver_version);
          //read thread id
          fthread_id:= byte(pchar(longint(fnet.read_pos+curpos)+1)^)+
                       byte(pchar(longint(fnet.read_pos+curpos+2))^)shl 8+
                       byte(pchar(longint(fnet.read_pos+curpos+3))^)shl 16+
                       byte(pchar(longint(fnet.read_pos+curpos+4))^)shl 24;
          curpos:=curpos+5;
          //get scramble buffer
          fscramble_buff:=copy(strpas(pchar(fnet.read_pos+curpos)),1,8);
          fscramble_buff[9]:=#0;
          curpos:=curpos+9;
          //read server capabilities
          if (pkt_length >= (longint(fnet.read_pos+curpos)+1 - (fnet.read_pos))) then
             fserver_capabilities:=byte(pchar(longint(fnet.read_pos+curpos))^)+
                                   byte(pchar(longint(fnet.read_pos+curpos+1))^)shl 8;
          //if we have server language and server status
          if (pkt_length >= (longint(fnet.read_pos+curpos)+18 - fnet.read_pos)) then
          begin
               fserver_language:=byte(pchar(fnet.read_pos+curpos)[2]);
               fserver_status:=byte(pchar(fnet.read_pos+curpos+3)[0])+byte(pchar(fnet.read_pos+curpos+3)[1])shl 8;
          end;

          //time to do some writing
          fclient_flag:=fclient_flag or CLIENT_CAPABILITIES;
          {$IFDEF HAVE_SSL}
          if (fuse_ssl) then
             fclient_flag:=fclient_flag or CLIENT_SSL;
          {$ENDIF}
          //if initial db is specified
          if (fdb<>'') then
             fclient_flag:=fclient_flag or CLIENT_CONNECT_WITH_DB;
          //if we have compression can we enable it?
          {$IFDEF HAVE_COMPRESS}
          if ((fserver_capabilities and CLIENT_COMPRESS=CLIENT_COMPRESS) and
             (fcompress or (fclient_flag and CLIENT_COMPRESS=CLIENT_COMPRESS))) then
             fclient_flag:=fclient_flag or CLIENT_COMPRESS
          else
          {$ENDIF} // seems we don't use/need compression
              fclient_flag:=fclient_flag and not(CLIENT_COMPRESS);
          {$IFDEF HAVE_SSL}
          if ((fserver_capabilities AND CLIENT_SSL=CLIENT_SSL) and
             (fuse_ssl or (fclient_flag and CLIENT_SSL=CLIENT_SSL))) then
             fclient_flag := fclient_flag or CLIENT_SSL //this does nothing
          else
          if (fclient_flag and CLIENT_SSL=CLIENT_SSL) then
          begin
               fclient_flag :=fclient_flag and (not (CLIENT_SSL));
               fuse_ssl:=false;
          end;
          {$ENDIF}
          //set client flags in buffer
          buff[0]:=chr(fclient_flag);
          buff[1]:=chr(fclient_flag shr 8);
          {$IFDEF HAVE_SSL}
          if (fclient_flag AND CLIENT_SSL=CLIENT_SSL) then
          begin
          if ((fnet.my_net_write(@buff,2)<>0) or (fnet.net_flush<>0)) then
          begin
               fnet.net_close;
               result:=false;
               exit;
          end;
          apc:=pchar(fssl_cipher);
          fnet.SwitchToSSL(pchar(fssl_key),pchar(fssl_cert),pchar(fssl_ca),pchar(fssl_capath),apc, fconnect_timeout);
          fssl_cipher:=apc;
          if (fnet.vio_type<>VIO_TYPE_SSL)and(fclient_flag and CLIENT_SSL=CLIENT_SSL) then
          begin
               fclient_flag :=fclient_flag and (not (CLIENT_SSL));//clear ssl flag
               result:=false; //mark error on ssl
               fuse_ssl:=false;
               SSL_ReadError;
               exit;
          end;
          end;
          {$ENDIF}
          //set max allowed packet
          pchar(longint(@buff)+2)[0]:=chr(max_allowed_packet);
          pchar(longint(@buff)+2)[1]:= chr(max_allowed_packet shr 8);
          pchar(longint(@buff)+2)[2]:= chr(max_allowed_packet shr 16);
          //do we have an user name?
          if (fuser <>'') then
          begin
               i:=length(fuser);
               if i>32 then //is it longer than 32
                  i:=32;
               move(pchar(@fuser[1])[0],pchar(@buff[5])^,i); //copy it to the buffer
               curpos:=i+5+1;
          end
          else
              curpos:=6;
          //if we have password
          if (fpasswd<>'') then
          begin
               somp:=mysql_scramble(pchar(@fpasswd[1]),pchar(@fscramble_buff[1]));
               //i:=strlen(somp);
               i:=8;
               move(somp[0],pchar(@buff[curpos])^,i);
               strdispose(somp);
               curpos:=curpos+i+1;
          end
          else
              inc(curpos);
          //do we have a db?
          if (fdb<>'') and ((fserver_capabilities and CLIENT_CONNECT_WITH_DB)=CLIENT_CONNECT_WITH_DB) then
          begin
               i:=length(fdb);
               if i>NAME_LEN then
                  i:=NAME_LEN;
               move(pchar(@fdb[1])[0],pchar(@buff[curpos])^,i);
               curpos:=curpos+i;
          end
          else
              inc(curpos);
          //we have the buffer filled, let's send it
          if (fnet.my_net_write(@buff,curpos)<>0) then
          begin //errors?
               fnet.net_close;
               result:=false;
               exit;
          end;
          //let's flush it
          if (fnet.net_flush<>0) then
          begin //errors?
               fnet.net_close;
               result:=false;
               exit;
          end;
          //did it got to the server? are we logged in?
          if (fnet.net_safe_read = packet_error) then
          begin //errors?
               fnet.net_close;
               result:=false;
               exit;
          end;
          //we use compression? let's tell to net to activate it
          if (fclient_flag and CLIENT_COMPRESS = CLIENT_COMPRESS)then
             fnet.compress:=true
          else
              fnet.compress:=false;
          //we are ready to work
          fstatus:=MYSQL_STATUS_READY;
          //if server does not support connect with db
          //we need to select the db
          if (fdb<>'') and (not ((fserver_capabilities and CLIENT_CONNECT_WITH_DB)=CLIENT_CONNECT_WITH_DB))and (not select_db(fdb)) then
          begin //errors on select db?
               fnet.net_close;
               result:=false;
               exit;
          end;
     end
     else //we are not connected
          result:=false;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
//sends a query to the server and attempts to read the result
// if StoreResult is true then it will create a result in store mode, else it will be used
// rather than creating an empty result to mark an ok executed query ExecutedOk variable
// will be set to true
// !! Pay attention to it since it is the only way to know if a query with no
// result set was executed ok
function TMysqlClient.query(const aquery: string; StoreResult:boolean; var ExecutedOk:boolean): TMysqlResult;
begin
     result:=nil;
     executedOk:=false;
     if freconnect then
        if not ping then//this will reconnect if we lost the connection in the mean time
           exit;
     if (simple_command(COM_QUERY,aquery,length(aquery),true,freconnect)=0) then
        if read_query_result=0 then
        begin
             if StoreResult then
             begin
                  result:=store_result;
                  fnet.net_pack;//we can pack the net now
             end
             else
                 result:=use_result;
             executedOk:=true;
        end
end;

////////////////////////////////////////////////////////////////////////////////
//sends a query by using SQL property to the server and attempts to read the result
// if StoreResult is true then it will create a result in store mode, else it will be used
// rather than creating an empty result to mark an ok executed query ExecutedOk variable
// will be set to true
// !! Pay attention to it since it is the only way to know if a query with no
// result set was executed ok
function TMysqlClient.query1(StoreResult: boolean;
var ExecutedOk: boolean): TMysqlResult;
begin
  result:=query(fsql.Text,StoreResult,ExecutedOk);
end;

function TMysqlClient.Exec : TMysqlResult;
var ExecutedOK : boolean; // dummy
begin
  result:=query(fsql.Text,true,ExecutedOk);
end;

////////////////////////////////////////////////////////////////////////////////
// tells to server to performs a refresh
function TMysqlClient.refresh(options: longint): boolean;
var buff:string[3];
begin
  buff[0]:=chr(options);
  buff[1]:=chr(options shr 8);
  buff[2]:=chr(options shr 16);
  buff[3]:=chr(options shr 24);
  result:=simple_command(COM_REFRESH,buff,4,false,freconnect)=0;
end;

////////////////////////////////////////////////////////////////////////////////
// attempt to change the current selected db
function TMysqlClient.select_db(const newdb: string): boolean;
begin
     result:=simple_command(COM_INIT_DB,newdb,length(newdb),false,freconnect)=0;
     if result then
        fdb:=newdb;
end;

////////////////////////////////////////////////////////////////////////////////
// tells to server to shutdown
// current logged in user will need permission to do that
function TMysqlClient.shutdown: boolean;
begin
     result:=simple_command(COM_SHUTDOWN,'',0,false,freconnect)=0;
     close;
end;

////////////////////////////////////////////////////////////////////////////////
// get the statistics from server
function TMysqlClient.stat: string;
begin
     if (simple_command(COM_STATISTICS,'',0,false,freconnect)<>0) then //try to send the command
        result:=''//fnet.last_error //there was an error
     else //no error
         begin
              if pchar(fnet.read_pos)[0]=#0 then //did we got an empty string?
              begin
                   fnet.last_errno:=CR_WRONG_HOST_INFO;
                   fnet.last_error:= client_errors[(fnet.last_errno)-CR_MIN_ERROR];
                   result:='';//fnet.last_error;
              end
              else
                  result:=strpas(pchar(fnet.read_pos)); //return stats
         end;
end;

////////////////////////////////////////////////////////////////////////////////
// reconnects to the server
// returns true if success
function TMysqlClient.reconnect: boolean;
begin
     if (not freconnect) or
        (fserver_status and SERVER_STATUS_IN_TRANS =SERVER_STATUS_IN_TRANS) then
     begin
          fserver_status:=fserver_status and not SERVER_STATUS_IN_TRANS;
          result:=false;
          exit;
     end;
     //fnet.net_close;
     if not connect1 then
        result:=false
     else
         result:=true;
end;

////////////////////////////////////////////////////////////////////////////////
// internal send file to server for use with load data infile on client machine
function TMysqlClient.send_file_to_server(const filename: string): longint;
var readcount:longint;
    buf:array[0..IO_SIZE*15-1] of char;
    f:file;
    tmp:byte;
begin
     //todo     fn_format(buf,filename,"","",4);
     assignfile(f,filename);
     tmp:=filemode; //old filemode
     filemode:=0; //read only
     {$I-}
     reset(f,1); //try to open the file
     {$I+}
     if (IOResult<> 0) then
     begin
          fnet.last_errno:=0;// EE_FILENOTFOUND
          fnet.last_error:=copy(format('File ''%s'' not found (Errcode: %d)',[filename,IOResult]),1,length(fnet.last_error));
          fnet.my_net_write('',0); //send empty packet to server
          fnet.net_flush;
          result:=-1;
          filemode:=tmp;
          exit;
     end;
     blockread(f,buf,sizeof(buf),readcount); //let's send the file
     while (readcount > 0) do //while we still have things in file
     begin
          if (fnet.my_net_write(buf,readcount)<>0) then //maybe we have errors?
          begin
               fnet.last_errno:=CR_SERVER_LOST;
               fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
               closefile(f);
               result:=-1;
               filemode:=tmp;
               exit;
          end;
          blockread(f,buf,sizeof(buf),readcount); //read next chunk
     end;
     closefile(f); //close the file
     if (fnet.my_net_write('',0)<>0) or (fnet.net_flush<>0) then //send empty packet to mark eof
     begin
          fnet.last_errno:=CR_SERVER_LOST;
          fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          result:=-1;
          filemode:=tmp;
          exit;
     end;
     if (readcount < 0) then //did by any chance we had an error while reading?
     begin
          fnet.last_errno:=2;//EE_READ
          fnet.last_error:=copy(format('Error reading file ''%s'' (Errcode: %d)',[filename,IOResult]),1,MYSQL_ERRMSG_SIZE-1);
          result:=-1;
          filemode:=tmp;
          exit;
     end;
     filemode:=tmp; //restore filemode
     result:=0;
end;

////////////////////////////////////////////////////////////////////////////////
//returns client version
function TMysqlClient.GetClientInfo: string;
begin
     result:=MYSQL_SERVER_VERSION;
end;

////////////////////////////////////////////////////////////////////////////////
// returns protocol version - one should read this only after connecting
// or else will be 0
function TMysqlClient.Getprotocol_version: cardinal;
begin
     result:=fnet.protocol_version;
end;

////////////////////////////////////////////////////////////////////////////////
//internal function to send a command to the server
function TMysqlClient.simple_command(command: TEnumServerCommand;
  arg: string; lengt: Integer; skipp_check: boolean; retry:boolean): longint;
var pl:longint;
begin
     result:= -1; //mark error unless ok
     if not fnet.net_connected then //are we connected?
     begin
          if not(reconnect) then //attempt to reconnect
          begin
               //preserve the error on connect
               //fnet.last_errno:=CR_SERVER_GONE_ERROR;
               //fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
               exit;
          end
     end;
     if (fstatus <> MYSQL_STATUS_READY) then //can we execute this command?
     begin
          fnet.last_errno:=CR_COMMANDS_OUT_OF_SYNC;
          fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          exit;
     end;
     fnet.last_error:=''; //init for command
     fnet.last_errno:=0;
     finfo:='';
     faffected_rows:= 0;
     finsert_id:=0;
     fnet.net_clear;
     if (fnet.net_write_command(chr(ord(command)),pchar(@arg[1]),lengt )<>0) then //let's try to send
     begin
          fnet.net_close;//end_server
          free_old_query;
          if reconnect or (fnet.net_write_command(chr(ord(command)),pchar(@arg[1]),lengt)<>0)then //another attempt to reconnect end send
          begin
               //failed
               fnet.last_errno:=CR_SERVER_GONE_ERROR;
               fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
               exit;
          end;
     end;
     result:=0; //no error
     if (not skipp_check) then //if we need to check if server got it
     begin
          pl:=fnet.net_safe_read; //read length of next packet
          if pl = packet_error then //if there is something
          begin
               if fnet.last_errno=CR_SERVER_LOST then
                  close;
               if retry then //one more time, but in order to not make it infinite loop this time will not retry
                  result:=simple_command(command,arg,lengt,skipp_check,false) //this time we do not retry
               else
                   result:=-1;
          end
          else
              result:=0; //ok
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// returns last error string (mapped on NET, actually down to VIO)
function TMysqlClient.GetLastError: string;
begin
     result:=fnet.last_error;
end;

////////////////////////////////////////////////////////////////////////////////
// reads one row from the server
// returns 0 if no error
// returns 1 if there arent anymore rows
function TMysqlClient.read_one_row(fields:longint;row:TMysql_Row;lengths:PCardinal): longint;
var field:longint;
    pkt_len,_len:longint;
    _pos,prev_pos:PChar;
begin
     // is there anything to read?
     pkt_len:=fnet.net_safe_read;
     if (pkt_len=packet_error) then
     begin
          result:=-1;
          exit;
     end;
     // is it the last row?
     if (pkt_len = 1) and(pchar(fnet.read_pos)[0] = #254) then
     begin
          result:=1;
          exit;
     end;
     //free row content
     for field:=0 to fields -1 do
         strdispose(TPPCA(row^)[field]);
     //read next row
     prev_pos:= nil;
     _pos:=pchar(fnet.read_pos);
     // for each field value
     for field:=0 to fields-1 do
     begin
          //get field value size
          _len:=net_field_length(longint(_pos));
          if (_len=NULL_LENGTH) or (_len=0) then
             begin
                  TPPCA(row^)[field]:=nil; //empty value
                  TPCA(lengths^)[field]:=0;
             end
          else
              begin
                    TPPCA(row^)[field]:=StrAlloc(_len+1);
                    //copy field content
                    move(_pos[0],TPPCA(row^)[field]^,_len);
                    TPPCA(row^)[field][_len]:=#0;// if one uses pchar
                    _pos:=_pos+_len;
                    TPCA(lengths^)[field]:=_len;
              end;
          if (prev_pos<>nil)and(prev_pos[0]<>#0)then //if previous field value didnt ended by #0
             prev_pos[0]:=#0;
          prev_pos:=_pos; //move to next
     end;
     prev_pos[0]:=#0; //set the last #0
     result:=0;
end;

////////////////////////////////////////////////////////////////////////////////
// reads rows from the server
// returns data if no error
// returns nil if there were any errors
function TMysqlClient.read_rows(mysql_fields: PMysql_FieldDef; fields: Integer; var hadErrors:boolean): PMYSQL_DATA;
var pkt_len,field,len1:longint;
    cp:pchar;
    prev_ptr:PMysql_Rows;
    cur:PMysql_Rows;
begin
     result:=nil;
     hadErrors:=true;
     pkt_len:=fnet.net_safe_read; //is there any data?
     if (pkt_len= packet_error) then
        exit;
     new(result);
     if (result=nil) then //out of memory?
     begin
          fnet.last_errno:=CR_OUT_OF_MEMORY;
          fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          exit;
     end;
     result^.data:=nil;
     prev_ptr:= nil;
     result^.rows:=0;
     result^.fields:=fields;
     cp:=pchar(fnet.read_pos);
     while ( byte(cp[0]) <> 254) and (pkt_len <> 1) do //do this until we get last row
     begin
          //here you could add a progress or something
          //like an event onNewRow <-disadvantage you can't tell how many left
          result^.rows:=result^.rows; //we have new row
          //let's grab some memory for the new row
          new(cur);
          if cur<>nil then
             cur^.data:=allocmem((fields)*sizeof(pchar));
          if (cur=nil) or (cur^.data=nil) then
          begin //mmm.. we are running out of memory
               free_rows(result);
               fnet.last_errno:=CR_OUT_OF_MEMORY;
               fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
               result:=nil;
               exit;
          end;
          cur^.Next:=nil; //so far we assume no more rows
          cur^.prior:=prev_ptr; //double link
          if prev_ptr<>nil then
             prev_ptr^.Next:= cur //preserve next link
          else
              result^.data:=cur;//it is the first / head
          prev_ptr:=cur;
          for field:=0 to fields-1 do //for each field
          begin
               len1:=net_field_length(longint(cp));
               if (len1 = 0)or(len1 = NULL_LENGTH) then //if it is an empty field
                  TPPCA(cur^.data^)[field]:=nil
               else
               begin
                    //let's grab some memory
                    TPPCA(cur^.data^)[field]:=StrAlloc(len1+1);
                    //copy field content
                    move(cp[0],TPPCA(cur^.data^)[field]^,len1);
                    TPPCA(cur^.data^)[field][len1]:=#0;// if one uses pchar
                    cp:=pchar(longint(cp)+len1); //we can move to next field
                    if (mysql_fields<>nil) then //if we passed fields structure
                    begin //we can check max_length
                         if  TPFDA(mysql_fields)[field].Max_Length < cardinal(len1) then
                             TPFDA(mysql_fields)[field].Max_Length := cardinal(len1);
                    end;
               end;
          end;
          pkt_len:=fnet.net_safe_read; //let's try to read next row /if any
          if ( pkt_len= packet_error) then
          begin //maybe we got an error
               free_rows(result); //we can free the rows
               result:=nil;
               exit;
          end;
          cp:=pchar(fnet.read_pos); //here we go again .. next row
     end;
     hadErrors:=false;
end;

////////////////////////////////////////////////////////////////////////////////
// internal decode of PMysql_Data into fields structure
function TMysqlClient.unpack_fields(data: PMYSQL_DATA; fields: Integer; long_flag_protocol: boolean): PMysql_FieldDef;
var field:PMysql_FieldDef;
    row:PMysql_Rows;
    aFieldVal:pchar;
begin
     //let's grab some memory
     getmem(result,sizeof(TMysql_FieldDef)*fields);
     field:=result;
     if (result=nil) then //out of memory?
        exit;
     row:=data^.data; //first row=first field def
     while row<>nil do
     begin
          //table
          aFieldVal:=TPPCA(row^.data^)[0];
          field^.Table:=StrNew(aFieldVal);
          //name
          aFieldVal:=TPPCA(row^.data^)[1];
          field^.Name:=strnew(aFieldVal);
          //length
          aFieldVal:=TPPCA(row^.data^)[2];
          if aFieldVal<>nil then
             field^.length:= (byte(pchar(aFieldVal)[0]))+
                            (byte(pchar(aFieldVal)[1]))shl 8+
                            (byte(pchar(aFieldVal)[2]))shl 16;
          //field type
          aFieldVal:=TPPCA(row^.data^)[3];
          if aFieldVal<>nil then
             field^.FieldType:= byte(pchar(aFieldVal)[0]);
          //NUM_FLAG is not send from server so it needs to be set
          if (field^.FieldType<=FIELD_TYPE_INT24) AND ((field^.FieldType<>FIELD_TYPE_TIMESTAMP) OR (field^.Length=14) OR (field^.Length=8)) OR (field^.FieldType=FIELD_TYPE_YEAR) then
             field^.flags:=field^.flags or NUM_FLAG;
          //flags and decimals
          aFieldVal:=TPPCA(row^.data^)[4];
          if aFieldVal<>nil then
          begin
               if (long_flag_protocol) then
               begin
                    field^.flags:= (byte(pchar(aFieldVal)[0]))+
                                  (byte(pchar(aFieldVal)[1]))shl 8;
                    field^.decimals:=byte(pchar(aFieldVal)[2]);
               end
               else
               begin
                    field^.flags:= byte(pchar(aFieldVal)[0]);
                    field^.decimals:=byte(pchar(aFieldVal)[1]);
               end;
          end;
          //default value
          //field.def:=nil; //*** removed
          //aFieldVal:=TPPCA(row.data^)[5];
          //if (aFieldVal<>nil)and(data.fields=6) then //if there are 6 fields on PMysql_Data
             //field.def:=strnew(aFieldVal);
          field^.Max_Length:= 0; //for the moment we don't know the max_length
          row := row^.next; //next field def
          field:=PMysql_FieldDef(longint(field)+SizeOF(TMysql_FieldDef));
     end;
     free_rows(data); //we can now free data since all values are in fields
end;

////////////////////////////////////////////////////////////////////////////////
// closes the connection to mysql server
procedure TMysqlClient.close;
var rec:boolean;
begin
     //init internal variables
     fscramble_buff:='';
     fthread_id:=0;
     faffected_rows:=0;
     finsert_id:=0;
     fstatus:=MYSQL_STATUS_READY;
     fserver_version:='';
     fserver_capabilities:=0;
     fserver_status:=SERVER_STATUS_AUTOCOMMIT;
     fserver_language:=0;
     fextra_info:=0;
     finfo:='';
     if fnet.net_connected then //are we connected?
     begin
          free_old_query; //if we have anything in buffer
          fstatus:=MYSQL_STATUS_READY;
          rec:=freconnect; //preserve reconnect state
          freconnect:=false;
          simple_command(COM_QUIT,'',0,true,freconnect); //tell the server we go
          fnet.net_close;
          freconnect:=rec;
          //should init all server variables
     end;
     if assigned(fusedresult) then
     begin
          fusedresult.fhandle:=nil; //break the link
          fusedresult:=nil;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// reads a query result
function TMysqlClient.read_query_result:longint;
var pos1:longint;
    field_count:longint;
    fields:pointer;
    length1:longint;
    error:longint;
    ae:boolean;
begin
     //anything to be read?
     length1 := fnet.net_safe_read;
     if (length1= packet_error) then
     begin
          result:=-1;
          exit;
     end;
     free_old_query; //if we had something before

     pos1:=fnet.read_pos;
     field_count:= net_field_length(pos1); //how many fields?

     while (field_count = NULL_LENGTH) do //send file to server
     begin
          error:=send_file_to_server(strpas(pchar(pos1)));
          length1:=fnet.net_safe_read;
          if ( length1= packet_error) or (error<>0)then //any errors?
          begin
               result:=-1;
               exit;
          end;
          pos1:=fnet.read_pos; //maybe we need to send another file
          field_count:= net_field_length(pos1);
     end;
     //no fields ... it was an executed query (eg insert)
     if (field_count = 0) then
     begin
          faffected_rows:= net_field_length_ll(pos1); //affected rows
          finsert_id:=net_field_length_ll(pos1); //last insert id
          //we can check for server status
          if (fserver_capabilities and CLIENT_TRANSACTIONS=CLIENT_TRANSACTIONS) then
          begin
               fserver_status:=byte(pchar(pos1)[0])+byte(pchar(pos1)[0])shl 8;
               pos1:=pos1+2;
          end;
          //aditional info
          if (pos1 < fnet.read_pos+length1) and (net_field_length(pos1)<>0) then
             finfo:=strpas(pchar(pos1));
          result:=0; //no errors
          exit;
     end;
     //we can switch the server in transaction
     if not (fserver_status and SERVER_STATUS_AUTOCOMMIT=SERVER_STATUS_AUTOCOMMIT) then
        fserver_status:=fserver_status or SERVER_STATUS_IN_TRANS;
     //get the extra info
     fextra_info:= net_field_length_ll(pos1);
     //now we can read result fields
     fields:=read_rows(nil,5,ae);
     if fields=nil then
     begin //out of memory?
          result:=-1;
          exit;
     end;
     //time to decode the fields
     ffields:=unpack_fields(PMYSQL_DATA(fields),field_count,fserver_capabilities and CLIENT_LONG_FLAG=CLIENT_LONG_FLAG);
     if (ffields=nil)then //out of memory?
     begin
          result:=-1;
          exit;
     end;
     //time to mark the waiting for result
     fstatus:=MYSQL_STATUS_GET_RESULT;
     ffield_count:=field_count;
     result:=0; //no errors
end;


////////////////////////////////////////////////////////////////////////////////
// lists the processes on the server
function TMysqlClient.list_processes: TMysqlResult;
var fields1:PMysql_Data;
    _pos:pchar;
    ae:boolean;
begin
     result:=nil;
     //send the command
     if (simple_command(COM_PROCESS_INFO,'',0,false,freconnect)<>0)then //if any errors
        exit;
     free_old_query; //if we had anything before
     //we can read the fields
     _pos:=pchar(fnet.read_pos);
     ffield_count:= net_field_length(longint(_pos));
     fields1:=read_rows(nil,5, ae);
     if (fields1 = nil)then
         exit;
     //decode them
     ffields:=unpack_fields(fields1,ffield_count,fserver_capabilities and CLIENT_LONG_FLAG=CLIENT_LONG_FLAG);
     if (ffields=nil) then
        exit;
     //we have the fields
     //we can now read the result
     fstatus:=MYSQL_STATUS_GET_RESULT;
     result:=store_result;
end;

////////////////////////////////////////////////////////////////////////////////
// internal stores the query result
function TMysqlClient.store_result: TMysqlResult;
var ae:boolean;
begin
     result:=nil;
     //do we have anything to store?
     if (ffields=nil) then
        exit;
     //is the right order?
     if (fstatus <> MYSQL_STATUS_GET_RESULT) then
     begin
          fnet.last_errno:=CR_COMMANDS_OUT_OF_SYNC;
          fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          exit;
     end;
     result:=TMysqlResult.create(self,rtStored);
     if (result=nil)then //out of memory?
     begin
          fnet.last_errno:=CR_OUT_OF_MEMORY;
          fnet.last_error:= client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          exit;
     end;
     //grab some memory for lengths - we use only one set of rowslengths for entire recordset
     getmem(result.flengths,ffield_count*sizeof(cardinal));
     if (result.flengths=nil)then //out of memory?
     begin
          fnet.last_errno:=CR_OUT_OF_MEMORY;
          fnet.last_error:= client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          result.free;
          result:=nil;
          exit;
     end;
     //we can read the records
     result.fdata:=read_rows(ffields,ffield_count, ae);
     result.fdata_cursor:=result.fdata^.data;
     if result.fdata_cursor<>nil then
     begin
          result.fcurrent_row:=result.fdata_cursor^.data;
          result.fEOF:=false;
          result.fRecNo:=0;
     end
     else
     begin
         result.fcurrent_row:=nil;
         result.fEOF:=true;
     end;
     result.ffields:=ffields;
     result.ffieldscount:=result.fdata^.fields;
     result.frowscount:=result.fdata^.rows;
     if ae then
        result.fLastRow:=-1 //means there was an error when reading
     else
         result.fLastRow:=1; //1 means the last row has been read without any errors
     faffected_rows:= result.frowscount;
     ffields:=nil;
     ffield_count:=0;
     fstatus:=MYSQL_STATUS_READY;
end;

////////////////////////////////////////////////////////////////////////////////
// internal creates a new result in use mode
// this means you read one row at a time ... very large memory savings if you
// don't need the entyre recordset ... ideal for processing data
function TMysqlClient.use_result: TMysqlResult;
var i:integer;
begin
     result:=nil;
     //is there anything to store?
     if (ffields=nil) then
        exit;
     //is it in the right order?
     if (fstatus <> MYSQL_STATUS_GET_RESULT) then
     begin
          fnet.last_errno:=CR_COMMANDS_OUT_OF_SYNC;
          fnet.last_error:=client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          exit;
     end;
     //let's create a new result
     result:=TMysqlResult.create(self,rtUsed);
     if (result=nil)then //out of memory?
     begin
          fnet.last_errno:=CR_OUT_OF_MEMORY;
          fnet.last_error:= client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          exit;
     end;
     //grab some memory for lengths
     getmem(result.flengths,ffield_count*sizeof(cardinal));
     if (result.flengths=nil)then //out of memory?
     begin
          fnet.last_errno:=CR_OUT_OF_MEMORY;
          fnet.last_error:= client_errors[(fnet.last_errno)-CR_MIN_ERROR];
          result.free;
          result:=nil;
          exit;
     end;
     //create a row for use
     result.frow:=allocmem((ffield_count)*sizeof(pchar));
     result.fcurrent_row:=result.frow;

     if (result.frow=nil) then //out of memory?
     begin
          FreeMem(result.flengths);
          result.free;
          result:=nil;
          exit;
     end;
     result.ffields:=ffields;
     for i:=0 to result.ffieldscount-1 do
         TPPCA(result.frow^)[i]:=nil;
     result.frowscount:=0;
     result.ffieldscount:=ffield_count;
     fstatus:=MYSQL_STATUS_USE_RESULT; //block other queryes
     fusedresult:=result; //set the link
     result.Next;//read first row
     result.fBOF:=true; //next has reset it ..
     ffields:=nil;
     ffield_count:=0;
end;

////////////////////////////////////////////////////////////////////////////////
// internal free of a previous query
procedure TMysqlClient.free_old_query;
var i:longint;
    afp:TMysql_fieldDef;
begin
     if (ffields<>nil) then
     begin
          for i:=0 to ffield_count-1 do //free the fields content
          begin
               afp:=TPFDA(ffields)[i];
               strdispose(afp.Name);
               strdispose(afp.Table);
               //strdispose(afp.Def);//*** removed
               afp.Name:=nil;
               afp.Table:=nil;
               //afp.Def:=nil;//*** removed
          end;
          freemem(ffields); //free fields pointer
     end;
     ffields:=nil;
     ffield_count:=0;
end;

////////////////////////////////////////////////////////////////////////////////
// another connect but without parameters (it uses the properties which are
// assumed to be set to the right value
function TMysqlClient.connect1: boolean;
begin
     result:=connect(fhost,fuser,fpasswd,fdb,fport,funix_socket,ftrysock,fclient_flag);
end;

////////////////////////////////////////////////////////////////////////////////
// set the host if we are not connected
procedure TMysqlClient.SetHost(const Value: string);
begin
     if (FHost<>value) and fnet.net_connected then
        fnet.net_close;
     FHost := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// sets db and if we are connected calls setdb
procedure TMysqlClient.SetDb(const Value: string);
begin
     fdb:=Value;
     if fnet.net_connected then
        select_db(value)
end;

////////////////////////////////////////////////////////////////////////////////
// sets password if we are not connected
procedure TMysqlClient.SetPasswd(const Value: string);
begin
     if (fpasswd<>value) and fnet.net_connected then
        fnet.net_close;
     FPasswd := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// sets port if we are not connected
procedure TMysqlClient.SetPort(const Value: cardinal);
begin
     if (FPort<>value) and fnet.net_connected then
        fnet.net_close;
     FPort := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// sets unix socket if we are not connected
procedure TMysqlClient.SetUnixSocket(const Value: string);
begin
     if (funix_socket<>value) and (fnet.net_connected) and fnamed_pipe then
        fnet.net_close;
     funix_socket := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// sets user if we are not connected
procedure TMysqlClient.SetUser(const Value: string);
begin
     if (FUser<>value) and fnet.net_connected then
        fnet.net_close;
     FUser := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// sets client flags if we are not connected
procedure TMysqlClient.SetClientFlag(const Value: cardinal);
begin
     if (fclient_flag<>value) and fnet.net_connected then
        fnet.net_close;
     fclient_flag := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// returns last error number
function TMysqlClient.GetLastErrorNo: cardinal;
begin
     result:=fnet.last_errno;
end;

////////////////////////////////////////////////////////////////////////////////
// returns true if we are connected
function TMysqlClient.GetConnected: boolean;
begin
     result:=fnet.net_connected;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of use named pipe
procedure TMysqlClient.SetNamedPipe(const Value: Boolean);
begin
     if (fnamed_pipe<>value) and fnet.net_connected then
        fnet.net_close;
     fnamed_pipe := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of try sockets
procedure TMysqlClient.SetTrySock(const Value: Boolean);
begin
     ftrysock := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of use ssl
procedure TMysqlClient.SetUseSSL(const Value: Boolean);
begin
     {$IFDEF HAVE_SSL}
     if (fuse_ssl<>value) and (fnet.net_connected) then
        fnet.net_close;
     fuse_ssl := Value;
     {$ELSE}
     fuse_ssl := false;
     {$ENDIF}
end;

{$IFDEF HAVE_SSL}
////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of ca
procedure TMysqlClient.Setsslca(const Value: string);
begin
     if (fssl_ca<>value) and (fnet.net_connected) and fuse_ssl then
        fnet.net_close;
     fssl_ca := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of capath
procedure TMysqlClient.Setsslcapath(const Value: string);
begin
     if (fssl_capath<>value) and (fnet.net_connected) and fuse_ssl then
        fnet.net_close;
     fssl_capath := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of cert
procedure TMysqlClient.Setsslcert(const Value: string);
begin
     if (fssl_cert<>value) and (fnet.net_connected) and fuse_ssl then
        fnet.net_close;
     fssl_cert := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of cipher
procedure TMysqlClient.Setsslcipher(const Value: string);
begin
     if (fssl_cipher<>value) and (fnet.net_connected) and fuse_ssl then
        fnet.net_close;
     fssl_cipher := Value;
end;

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of key
procedure TMysqlClient.Setsslkey(const Value: string);
begin
     if (fssl_key<>value) and (fnet.net_connected) and fuse_ssl then
        fnet.net_close;
     fssl_key := Value;
end;
{$ENDIF}

////////////////////////////////////////////////////////////////////////////////
// if we are not connected it sets the value of compress
procedure TMysqlClient.setfcompress(const Value: Boolean);
begin
     {$IFDEF HAVE_COMPRESS}
     if (fcompress<>value) and fnet.net_connected then
        fnet.net_close;
     fcompress := Value;
     {$ELSE}
     fcompress:=false;
     {$ENDIF}
end;

{$IFDEF HAVE_SSL}
////////////////////////////////////////////////////////////////////////////////
// if we had any errors on ssl this will return the next
function TMysqlClient.SSL_ReadError: boolean;
var l:longint;
    f,d:pchar;
    line,flags:longint;
    buf: array[0..199] of char;
begin
     l:=ERR_get_error_line_data(@f,@line,@d,@flags); //any errors?
     result:=false;
     if l<> 0 then
     begin //we had an error
          fnet.last_error:=format('OpenSSL: %s:%s:%d:%s\n',[ ERR_error_string(l,buf),  f,line,d]);
          fnet.last_errno:=l;
          result:=true;
     end;
end;
{$ENDIF}

//==============================================================================

//------------------------------------------------------------------------------
{ TMysql_Res }
//------------------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////
// creates a new result and initialize the default values
constructor TMysqlResult.create(aMysql: TMysqlClient; aType:TResultType);
begin
     inherited create;
     fhandle:=aMysql;
     fType:=aType;
     ffields:=nil;
     flengths:=nil;
     fdata:=nil;
     fdata_cursor:=nil;
     frow:=nil;
     flengthsread:=false;
     fRecNo:=-1;
     ffieldscount:=0;
     frowscount:=0;
     ffields:=nil;
     fcurrent_row:=nil;
     fBOF:=true;
     fLastRow:=0;
     fMyField := TMyField.Create;
end;

////////////////////////////////////////////////////////////////////////////////
// frees the result and internal values
destructor TMysqlResult.destroy;
var pkt_len:longint;
    i:integer;
    row,tmp:PMysql_Rows;
    afp:TMysql_FieldDef;
begin
     fMyField.Destroy;
     if ftype=rtUsed then //break the link
        if assigned(fhandle) then
           fhandle.fusedresult:=nil;
     if (fhandle<>nil) and (fhandle.fstatus = MYSQL_STATUS_USE_RESULT) then
     begin //is there anything on the buffer?
          while true do
          begin //clear the buffer
               pkt_len:=fhandle.fnet.net_safe_read;
               if ( pkt_len= packet_error) then
                  break;
               if (pkt_len = 1) and (pchar(fhandle.fnet.read_pos)[0] = #254) then
                  break;
          end;
          fhandle.fstatus:=MYSQL_STATUS_READY;
          fhandle.fusedresult:=nil;
          fhandle.fnet.net_pack; //we finished reading and we can pack the net
          fhandle.faffected_rows:= frowscount;
     end;
     //let's free the data in the result
     if fdata<>nil then
     begin
          row:=fdata^.data;
          while row<>nil do
          begin
               for i:=0 to ffieldscount-1 do //let's free the fields
                   strdispose(TPPCA(row^.data^)[i]);
               dispose(row^.data);
               tmp:=row;
               row:=row^.next;
               dispose(tmp); //we can free the row
          end;
          dispose(fdata);
     end;
     //do we have fields definitions?
     if (ffields<>nil) then
     begin //free them
          for i:=0 to ffieldscount-1 do
          begin
               afp:=TPFDA(ffields)[i];
               strdispose(afp.Name);
               strdispose(afp.Table);
               //strdispose(afp.Def);//*** removed
               afp.Name:=nil;
               afp.Table:=nil;
               //afp.Def:=nil;//*** removed
          end;
          freemem(ffields);
          ffields:=nil;
     end;
     freemem(flengths); //free the lengths buffer
     flengths:=nil;
     if (frow<>nil) then //free the row
     begin
          //free the last row
          for i:=0 to ffieldscount-1 do
              strdispose(TPPCA(frow^)[i]);
          freemem(frow);
     end;
     frow:=nil;
     inherited destroy;
end;

////////////////////////////////////////////////////////////////////////////////
// fills the flengths memory with actual values
procedure TMysqlResult.FetchLengths;
var i:longint;
begin
     flengthsread:=true;
     if fType=rtStored then
     begin
          if (fcurrent_row=nil)then //is there anything to fetch?
          begin
               for i:=0 to ffieldscount-1 do
                   TPCA(flengths^)[i]:=0;
               exit;
          end;
          for i:=0 to ffieldscount-1 do
          begin
               //get the sizes
               if TPPCA(fcurrent_row^)[i]<>nil then
                  TPCA(flengths^)[i]:=StrBufSize(pchar(TPPCA(fcurrent_row^)[i]))-1
               else
                   TPCA(flengths^)[i]:=0;
          end;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// returns field definition based on an index
// returns nil on invalid index
function TMysqlResult.FieldDef(aIndex: Integer): PMysql_FieldDef;
begin
     if (aIndex>-1) and (aIndex< ffieldscount) then //are we in range?
        result:=PMysql_FieldDef(longint(ffields)+aIndex*sizeof(TMysql_FieldDef))
//        result:=PMysql_FieldDef(@TPFDA(ffields)[aIndex])
     else
         result:=nil;
end;

////////////////////////////////////////////////////////////////////////////////
// returns the length of a field
// or 0 on invalid index
function TMysqlResult.FieldLength(aIndex: Integer):cardinal;
begin
     //make sure you read the lengths
     //if not flengthsread then //if we don't have the lengths then we need them
     //   fetch_lengths;
     result:=0;
     if (aIndex>=0) and (aIndex<ffieldscount)and flengthsread then //are we in range
        result:=TPCA(flengths^)[aIndex];
end;

////////////////////////////////////////////////////////////////////////////////
// returns a value as pchar based on its index in current row
function TMysqlResult.FieldValue(aIndex: Integer): pchar;
begin
  result:=nil;
  if (aIndex>-1) and (aIndex< ffieldscount) then //are we in range?
  begin
       if ftype=rtUsed then
          result:=TPPCA(frow^)[aIndex] //if it is used we have a single row
       else
           if fcurrent_row<>nil then
              result:=TPPCA(fcurrent_row^)[aIndex]; //else we access current row
  end
  else
    Raise Exception.CreateFmt('Index %d is out of range (%d..%d)',[aIndex,0,ffieldscount])
end;

////////////////////////////////////////////////////////////////////////////////
// goes to the first row in record
// it does nothing on the case of used result
procedure TMysqlResult.First;
begin
     fBOF:=true;
     if ftype=rtStored then
     begin
          if fdata^.data<>nil then
          begin
               fdata_cursor:=fdata^.data;//set first
               fcurrent_row:=fdata_cursor^.data; //set current row
               flengthsread:=false; //mark unknown lengths
          end;
          FEof:=fdata^.data=nil;
          if not FEof then
             FRecNo:=0
          else
              FRecNo:=-1;
     end
     else
         FEof:=frowscount=0;
end;

////////////////////////////////////////////////////////////////////////////////
// moves to the last row only if the result is not used
// it skips all the rpw until last one in the case of used result!!!!
// it should not be applied on USED result
procedure TMysqlResult.Last;
begin
     if (ftype=rtStored)then
     begin
          if (fdata_cursor<>nil) and (not feof) then
          begin
               //in the worst case we are at first row
               while (fdata_cursor^.next<>nil) do
                     fdata_cursor:=fdata_cursor^.next;
               fcurrent_row:=fdata_cursor^.data;
               flengthsread:=false;
          end;
          fEOF:=true;
          fBof:=fdata^.data=nil;
          fRecNo:=frowscount-1
     end
     else
     begin
          feof:=true;
          fBof:=frowscount=0;
          if not assigned(fhandle) then //mysqlclient gone .. we can't read anymore data
          begin
               if fLastRow=0 then
                  fLastRow:=-1; //mark error
               exit;
          end;
          //read all rows till the end or error
          fLastRow:=fhandle.read_one_row(ffieldscount,frow,flengths);
          while (fLastRow=0) do
          begin
               frowscount:=frowscount+1;//we got a new record we can exit
               fLastRow:=fhandle.read_one_row(ffieldscount,frow,flengths);
          end;
          fRecNo:=frowscount-1;
          if assigned(fhandle) then
          begin
               fhandle.fusedresult:=nil;
               fhandle.fstatus:=MYSQL_STATUS_READY;
               fhandle.fnet.net_pack;//we finished reading we can pack the net
               fhandle.faffected_rows:= frowscount;
               fhandle:=nil;
          end;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// moves to the previous row
procedure TMysqlResult.Prior;
begin
     if ftype=rtStored then
     begin
          if (fdata_cursor<>nil)and(fdata_cursor^.prior<>nil) then //can we move to prior?
          begin
               fdata_cursor:=fdata_cursor^.prior;
               fcurrent_row:=fdata_cursor^.data;
               flengthsread:=false;
               FRecNo:=FRecNo-1;
               fBof:=false;
          end
          else
              fBOF:=true; //we cant fBof is true
          fEof:=fdata^.data=nil;
     end
     else
     begin
          fBOF:=true; //if used there is no prior
          fEof:=frowscount=0;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// moves to the next row
procedure TMysqlResult.Next;
begin
     if ftype=rtUsed then
     begin
          FBof:=frowscount=0;
          fEof:=false;
          flengthsread:=true;
          if not assigned(fhandle) then
          begin //mysqlclient gone .. we can't read anymore data
               if fLastRow=0 then
                  fLastRow:=-1;//mark error
               feof:=true;
               exit;
          end;
          fLastRow:=fhandle.read_one_row(ffieldscount,TMysql_row(pointer(@frow)^),flengths);
          if (flastRow=0) then
          begin
               fRecNo:=frowscount;
               frowscount:=frowscount+1;//we got a new record we can exit
               exit;
          end
          else
          begin
               fEof:=true;
               //we should clear the result
               if assigned(fhandle) then
               begin
                    fhandle.fusedresult:=nil;
                    fhandle.fstatus:=MYSQL_STATUS_READY;
                    fhandle.fnet.net_pack; //we finished reading and we can pack the net
                    fhandle.faffected_rows:= frowscount;
                    fhandle:=nil;
               end;
          end;
     end
     else //result is stored
         begin
              if (fdata_cursor<>nil)and(fdata_cursor^.next<>nil) then //can we go to next?
              begin
                   fdata_cursor:=fdata_cursor^.next;
                   fcurrent_row:=fdata_cursor^.data;
                   fEof:=false;
                   flengthsread:=false;
                   fRecNo:=fRecNo+1;
              end
              else
                  feof:=true;
              fBof:=fdata^.data=nil;
         end;
end;

////////////////////////////////////////////////////////////////////////////////
// moves to the first row
{procedure TMysqlResult.SetBOF(const Value: boolean);
begin
     if Value then
        first
     else
         Next;
end;}

////////////////////////////////////////////////////////////////////////////////
// moves to the last row
{procedure TMysqlResult.SetEOF(const Value: boolean);
begin
     if Value then
        Last
     else
         Prior;
end;}

////////////////////////////////////////////////////////////////////////////////
// sets haslengths flags
procedure TMysqlResult.SetHasLengths(const Value: boolean);
begin
     if value and not flengthsread then
        FetchLengths;
end;

////////////////////////////////////////////////////////////////////////////////
// moves to a specific record defined by name 0 based
//not very efficient .. as soon as i'll get a chance i will optimize it
procedure TMysqlResult.SetRecNo(const Value: comp);
var i:comp;
begin
     if ftype=rtStored then
     if (Value>-1) and (Value<frowscount) then
        begin
             fBof:=false;
             fEof:=false;
             //move to first
             fdata_cursor:=fdata^.data;
             i := Value;
             while (fdata_cursor^.next<>nil) and (i>0) do
             begin
                  fdata_cursor:=fdata_cursor^.next;
                  i:=i-1;
             end;
             fRecNo := Value;
             fcurrent_row:=fdata_cursor^.data;
        end;
end;

////////////////////////////////////////////////////////////////////////////////
// returns true if there has been an error during the reading of the result
function TMysqlResult.GetHadErrors: boolean;
begin
     result:=fLastRow<0;
end;

////////////////////////////////////////////////////////////////////////////////
// returns true if there has been an error during the reading or if the last row had been read
function TMysqlResult.GetLastRowRead: boolean;
begin
     result:=fLastRow<>0;
end;

////////////////////////////////////////////////////////////////////////////////
// returns a field def based on a name or nil if there is no field with that name
function TMysqlResult.FieldDefByName(aName: string;
  CaseSensitive: boolean): PMysql_FieldDef;
begin
     result:=FieldDef(FieldIndexByName(aName,CaseSensitive));
end;

////////////////////////////////////////////////////////////////////////////////
// returns the index of a field with a specific name or -1 of there is no field with that name
function TMysqlResult.FieldIndexByName(aName: string;
  CaseSensitive: boolean): longint;
var i:integer;
begin
     result:=-1;
     if aName<>'' then
     begin
          for i:=0 to fFieldsCount-1 do
              if not CaseSensitive then
              begin
                   if uppercase(FieldDef(i)^.Name)=uppercase(aName) then
                   begin
                        result:=i;
                        break;
                   end;
              end
              else
                  if strpas(FieldDef(i)^.Name)=aName then
                  begin
                       result:=i;
                       break;
                  end;
     end;
     if Result = -1 then
       Raise Exception.CreateFmt('FieldName "%s" not found',[aName]);
end;

////////////////////////////////////////////////////////////////////////////////
// returns the value of a field with a specific name or nil if there is no field with that name
//note: there may be fields with nil value ... so do not take the result as there is no field with that name
function TMysqlResult.FieldValueByName(aName: string;
  CaseSensitive: boolean): pchar;
begin
  result:=FieldValue(FieldIndexByName(aName,CaseSensitive));
end;

function TMysqlResult.FieldByName(aName: string) : TMyField;
begin
  fMyField.Value := FieldValueByName(aName,false);
  (*
  if fMyField.Value = NIL then begin // fieldname not found
    raise Exception.CreateFmt('Fieldname "%s" not found',[aName]);
  end
  else
  *)
    Result := fMyField;
end;

function TMysqlResult.FieldByIndex(aIndex: LongInt) : TMyField;
begin
  fMyField.Value := FieldValue(aIndex);
  if fMyField.Value = NIL then begin // fieldname not found
    raise Exception.CreateFmt('Fieldindex "%d" not found',[aIndex]);
  end
  else
    Result := fMyField;
end;

{ TMyField by tam@gmx.de }
function TMyField.GetInteger: Integer;
begin
  // pChar -> Integer
  Result := StrToInt(StrPas(Value));
end;

function TMyField.GetBool : Boolean;
begin
  Result := StrPas(Value) = 'Y';
end;

function TMyField.GetString: String;
begin
  // pChar -> String
  if Value = NIL then
    Result := ''
    //raise Exception.Create('String is NULL')
  else
    Result := StrPas(Value);
end;

function TMyField.GetDateTime: TDateTime;
begin
  // pChar -> TDateTime
  if Value = NIL then // date is NULL
    raise Exception.Create('Date is NULL')
  else begin
    ShortDateFormat := 'yyyy-mm-dd';
    ShortTimeFormat := 'dd.nn.ss';
    DateSeparator := '-';
    Result := StrToDateTime(StrPas(Value));
  end;
end;

function TMyField.GetFloat : Real;
begin
  // pChar -> Float
  Result := StrToFloat(StrPas(Value));
end;

end.

