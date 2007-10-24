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
unit uMysqlVio;
////////////////////////////////////////////////////////////////////////////////
// VIO = Virtual Input Output
// supposed to hide low level read/write from the other 2 levels
// this will be controled and used by "net" no one should ever need to use it directly

interface

{$I mysqlinc.inc}

uses sysutils, uMysqlErrors, uMysqlCT {$IFDEF asl},aslSocket, OS2Socket,ioctl,sockin,netdb,utils{$ENDIF}{$IFDEF HAVE_SSL},uMysqlSSL{$ENDIF};

type
    TMysqlVio = class (TObject)
                private
                FSd : longint;
                FHPipe : longint;
                ffcntl_mode : longint;
                ftype : TEnumVioType;
                flast_error         : string[MYSQL_ERRMSG_SIZE];
                flast_errno         : cardinal;
                {$IFDEF HAVE_SSL}
                fssl                : pointer;
                fnewcon             : pointer;
                {$ENDIF}

                procedure Setlast_error(const Value: string);
                function Getlast_error: string;
                function fastsend:longint;
                function keepalive(onoff:boolean):longint;
                {$IFDEF HAVE_SSL}
                function new_VioSSLConnectorFd(const key:pchar;const cert:pchar;const ca:pchar;const capath:pchar;const cipher:pchar):pointer;
                {$ENDIF}
                public
                property fcntl_mode : longint read ffcntl_mode;
                property last_error : string read Getlast_error write Setlast_error;
                property last_errno : cardinal read flast_errno write flast_errno;
                property VIO_type : TEnumVioType read ftype;

                constructor create;
                destructor destroy; override;

                function vio_read (buf:pointer; const sz:longint):longint;
                function vio_write (buf:pointer; size:longint):longint;
                function vio_blocking(onoff:boolean):longint;
                function vio_intrerupted:boolean;
                function vio_should_retry:boolean;
                function vio_open( _type:TEnumVioType; host:string; unix_socket:string
                ; port:longint; connect_timeout:cardinal; trysock:boolean):longint;
                function vio_close:longint;
                function vio_poll_read(timeout:cardinal):boolean;
                {$IFDEF HAVE_SSL}
                procedure SwitchToSSL(const key:pchar;const cert:pchar;const ca:pchar;const capath:pchar;var cipher:pchar; timeout:cardinal);
                {$ENDIF}

                end;

////////////////////////////////////////////////////////////////////////////////
implementation
////////////////////////////////////////////////////////////////////////////////

const
     //poll constants
     IPPROTO_IP     =   0;
     IP_TOS         = {$IFDEF _WIN_}8;{$ELSE}1;{$ENDIF} //need check
     SOL_SOCKET     = {$IFDEF _WIN_}$ffff;{$ELSE}1;{$ENDIF} //need check
     SO_KEEPALIVE   = {$IFDEF _WIN_}$0008;{$ELSE}$0009;{$ENDIF} //need check
     IPPROTO_TCP    =   6;
     TCP_NODELAY    = $0001;
     FD_SETSIZE     =   {$IFDEF _WIN_}64;{$ELSE}1024;{$ENDIF} //need check
     POLLIN=1;
     POLLPRI=2;
     POLLOUT=4;
     POLLERR=8;
     POLLHUP=16;
     POLLNVAL=32;
     POLLRDNORM=POLLIN;
     POLLRDBAND=POLLPRI;
     POLLWRNORM=POLLOUT;
     POLLWRBAND=POLLOUT;
     POLL_CAN_READ=(POLLIN or POLLRDNORM );
     POLL_CAN_WRITE=(POLLOUT or POLLWRNORM or POLLWRBAND );
     POLL_HAS_EXCP=(POLLRDBAND or POLLPRI );
     POLL_EVENTS_MASK=(POLL_CAN_READ or POLL_CAN_WRITE or POLL_HAS_EXCP);
     {$IFDEF _WIN_}
     IOC_IN       = $80000000;
     IOCPARM_MASK = $7f;
     FIONBIO      = IOC_IN or { set/clear non-blocking i/o }
                  ((Longint(SizeOf(Longint)) and IOCPARM_MASK) shl 16) or
                  (Longint(Byte('f')) shl 8) or 126;
     {$ENDIF}

type
    //poll types for poll reading
    PFDSet = ^TFDSet;
    TFDSet = record
             fd_count: longint;
             fd_array: array[0..FD_SETSIZE-1] of longint;
             end;
    PTimeVal = ^TimeVal;
    TimeVal = record
              tv_sec: Longint;
              tv_usec: Longint;
              end;

    TPollFD = record
                    fd:longint;
                    events:smallint;
                    revents:smallint;
              end;
    {$IFNDEF _WIN_}
    PPollFD = ^TPollFD;
    {$ENDIF}

const
     AF_INET         = 2;
     SOCK_STREAM     = 1;
     SOCKET_ERROR    = -1;
     INADDR_NONE     = $FFFFFFFF;
{$IFNDEF _WIN_}
const
     F_SETFL = 4;
     F_GETFL = 3;
     __NFDBITS       = 8 * sizeof(cardinal);
     EAGAIN = 11;        {  Try again  }
     EINTR = 4;        {  Interrupted system call  }
{$ENDIF}

{$IFDEF _WIN_}
const
     WSABASEERR     = 10000;
     WSAEINTR       = (WSABASEERR+4);
     WSAEWOULDBLOCK = (WSABASEERR+35);
     WSAEINPROGRESS = (WSABASEERR+36);
     WSADESCRIPTION_LEN     =   256;
     WSASYS_STATUS_LEN      =   128;
{$ENDIF}
const INVALID_HANDLE_VALUE = -1;

(*
type
    PHostEnt = ^HostEnt;
    HostEnt = record
              h_name: PChar;
              h_aliases: ^PChar;
              h_addrtype: {$IFDEF _WIN_}Smallint;{$ELSE}longint;{$ENDIF}
              h_length: {$IFDEF _WIN_}Smallint;{$ELSE}cardinal;{$ENDIF}
              case Byte of
              0: (h_addr_list: ^PChar);
              1: (h_addr: ^PChar)
              end;

    SunB = packed record
           s_b1, s_b2, s_b3, s_b4: char;
           end;
    SunW = packed record
           s_w1, s_w2: word;
           end;
    in_addr = record
              case longint of
              0: (S_un_b: SunB);
              1: (S_un_w: SunW);
              2: (S_addr: longint);
              end;
*)
{$IFNDEF _WIN_}
type
    TSockAddr = record
                case Integer of
                0: (sa_family: word;
                   sa_data: packed array[0..13] of Byte);
                1: (sin_family: word;
                   sin_port: word;
                   sin_addr: in_addr;
                   sin_zero: packed array[0..7] of Byte);
                end;
{$ELSE}
    TSockAddr = record
                case longint of
                0: (sin_family: word;
                   sin_port: word;
                   sin_addr: in_addr;
                   sin_zero: array[0..7] of Char);
                1: (sa_family: word;
                   sa_data: array[0..13] of Char)
                end;
{$ENDIF}

{$IFDEF _WIN_}
type
    WSAData = record
              wVersion: Word;
              wHighVersion: Word;
              szDescription: array[0..WSADESCRIPTION_LEN] of Char;
              szSystemStatus: array[0..WSASYS_STATUS_LEN] of Char;
              iMaxSockets: Word;
              iMaxUdpDg: Word;
              lpVendorInfo: PChar;
              end;
//winsock imports
function setsockopt(s: longint; level, optname: longint; optval: PChar; optlen: longint): longint; stdcall; external 'wsock32.dll' name 'setsockopt';
function ioctlsocket(s: longint; cmd: cardinal; var arg: longint): longint; stdcall; external 'wsock32.dll' name 'ioctlsocket';
function send(s: longint; var Buf; len, flags: longint): longint; stdcall; external 'wsock32.dll' name 'send';
function recv(s: longint; var Buf; len, flags: longint): longint; stdcall; external 'wsock32.dll' name 'recv';
function WSAGetLastError: longint; stdcall; external 'wsock32.dll' name 'WSAGetLastError';
function __WSAFDIsSet(s: longint; var FDSet: TFDSet): LongBool; stdcall; external 'wsock32.dll' name '__WSAFDIsSet';
function select(nfds: longint; readfds, writefds, exceptfds: PFDSet; timeout: PTimeVal): Longint; stdcall; external 'wsock32.dll' name 'select';
function shutdown(s: longint; how: longint): longint; stdcall; external 'wsock32.dll' name 'shutdown';
function closesocket(s: longint): longint; stdcall; external 'wsock32.dll' name 'closesocket';
function WSACleanup: longint; stdcall; external 'wsock32.dll' name 'WSACleanup';
function WSAStartup(wVersionRequired: word; var WSData: WSAData): longint; stdcall; external 'wsock32.dll' name 'WSAStartup';
function socket(af, Struct, protocol: longint): longint; stdcall; external 'wsock32.dll' name 'socket';
function inet_addr(cp: PChar): longint; stdcall; external 'wsock32.dll' name 'inet_addr';
function gethostbyname(name: PChar): PHostEnt; stdcall; external 'wsock32.dll' name 'gethostbyname';
function htons(hostshort: longint): longint; stdcall; external 'wsock32.dll' name 'htons';
function connect(s: longint; var name: TSockAddr; namelen: longint): longint; stdcall; external 'wsock32.dll' name 'connect';

type
    //windows pipes type
    POverlapped = ^_Overlapped;
    _OVERLAPPED = record
                        Internal: cardinal;
                        InternalHigh: cardinal;
                        Offset: cardinal;
                        OffsetHigh: cardinal;
                        hEvent: cardinal;
                  end;
  PSecurityAttributes = ^TSecurity_Attributes;
  TSECURITY_ATTRIBUTES = record
    nLength: cardinal;
    lpSecurityDescriptor: Pointer;
    bInheritHandle: LongBOOL;
  end;
const
     //windows pipes constants
     GENERIC_READ             = cardinal($80000000);
     GENERIC_WRITE            = $40000000;
     OPEN_EXISTING = 3;
     ERROR_PIPE_BUSY = 231;
     PIPE_READMODE_BYTE = 0;
     PIPE_WAIT = 0;
//windows pipes functions
function WriteFile(hFile: cardinal; const Buffer; nNumberOfBytesToWrite: cardinal;
  var lpNumberOfBytesWritten: cardinal; lpOverlapped: POverlapped): longbool; stdcall; external 'kernel32.dll' name 'WriteFile';
function ReadFile(hFile: cardinal; var Buffer; nNumberOfBytesToRead: cardinal;
  var lpNumberOfBytesRead: cardinal; lpOverlapped: POverlapped): longbool; stdcall; external 'kernel32.dll' name 'ReadFile';
function CloseHandle(hObject: cardinal): longbool; stdcall;external 'kernel32.dll' name 'CloseHandle';
function CreateFile(lpFileName: PChar; dwDesiredAccess, dwShareMode: cardinal;
  lpSecurityAttributes: PSecurityAttributes; dwCreationDisposition, dwFlagsAndAttributes: cardinal;
  hTemplateFile: cardinal): cardinal; stdcall; external 'kernel32.dll' name 'CreateFileA';
function GetLastError: cardinal;  stdcall; external 'kernel32.dll' name 'GetLastError';
function WaitNamedPipe(lpNamedPipeName: PChar; nTimeOut: cardinal): LongBOOL; stdcall; external 'kernel32.dll' name 'WaitNamedPipeA';
function SetNamedPipeHandleState(hNamedPipe: cardinal; var lpMode: cardinal;
  lpMaxCollectionCount, lpCollectDataTimeout: Pointer): LongBOOL; stdcall; external 'kernel32.dll' name 'SetNamedPipeHandleState';
{$ENDIF}

{$IFNDEF asl}
{$IFNDEF _WIN_}
function fcntl(Handle: Integer; Command: Integer; Arg: Longint): Integer; external 'libc.so.6' name 'fcntl';overload;
function fcntl(Handle: Integer; Command: Integer): Integer; cdecl; external 'libc.so.6' name 'fcntl';overload;
function recv(fd: longint; var buf; n: cardinal; flags: Integer): Integer; cdecl;external 'libc.so.6' name 'recv';
function send(fd: longint; const buf; n: cardinal; flags: Integer): Integer; cdecl;external 'libc.so.6' name 'send';
function setsockopt(fd: longint; level, optname: Integer; optval: Pointer; optlen: cardinal): Integer; cdecl;external 'libc.so.6' name 'setsockopt';
function shutdown(fd: longint; how: Integer): Integer; cdecl;external 'libc.so.6' name 'shutdown';
function connect(fd: longint; const addr: tsockaddr; len: cardinal): Integer; cdecl;external 'libc.so.6' name 'connect';
function socket(domain, _type, protocol: Integer): longint; cdecl; external 'libc.so.6' name 'socket';
function inet_addr(cp: PChar): cardinal; cdecl;external 'libc.so.6' name 'inet_addr';
function gethostbyname(name: PChar): PHostEnt; cdecl;external 'libc.so.6' name 'gethostbyname';
function htons(hostshort: word): word; cdecl;external 'libc.so.6' name 'htons';
function poll(fds: PPollFD; nfds: cardinal; timeout: Integer): Integer; cdecl;external 'libc.so.6' name 'poll';
{$ENDIF}
{$ENDIF}

/////////////////////////////////////////////////////

{$IFNDEF _WIN_}
//var errno:longint;
{$ENDIF}
////////////////////////////////////////////////////////////////////////////////
{$IFDEF _WIN_}
var fwsaData:WSADATA; // on windows winsock
{$ENDIF}

{.$IFDEF _WIN_}
////////////////////////////////////////////////////////////////////////////////
procedure xFD_SET(Socket: longint; var FDSet: TFDSet);
begin
     if FDSet.fd_count < FD_SETSIZE then
     begin
          FDSet.fd_array[FDSet.fd_count] := Socket;
          Inc(FDSet.fd_count);
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// poll implementation using select
// not needed on linux

{function _poll(fds:TPollFD; timeout:longint):longint;
var err,n,count:longint;
    rfd,wfd,efd,ifd:tfdset;
    timebuf:timeval;
    tbuff:ptimeval;
    events,fd:longint;
    revents:longint;
begin
    tbuff :=nil;
    n := 0;
    ifd.fd_count:=0;
    rfd.fd_count:=0;
    wfd.fd_count:=0;
    efd.fd_count:=0;
    events := fds.events;
    fd := fds.fd;
    fds.revents := 0;
    if not((fd < 0) or (__WSAFDIsSet(fd, ifd))) then
    begin
         if (fd > n) then
            n := fd;
         if (events and POLL_CAN_READ)=POLL_CAN_READ then
            FD_SET(fd, rfd);
         if (events and POLL_CAN_WRITE)=POLL_CAN_WRITE then
            FD_SET(fd, wfd);
         if (events and POLL_HAS_EXCP)=POLL_HAS_EXCP then
            FD_SET(fd, efd);
    end;
    if(timeout >= 0) then
    begin
        timebuf.tv_sec := timeout div 1000;
        timebuf.tv_usec := (timeout div 1000) * 1000;
        tbuff := @timebuf;
    end;
    err := select(n+1,@rfd,@wfd,@efd,tbuff);
    if(err < 0) then
    begin
        result:=err;
        exit;
    end;
    count := 0;
    begin
        revents := (fds.events and POLL_EVENTS_MASK);
        fd := fds.fd;
        if(fd >= 0) then
        begin
             if (__WSAFDIsSet(fd, ifd))then
                revents := POLLNVAL
             else
             begin
                  if not(__WSAFDIsSet(fd, rfd)) then
                     revents :=revents and not POLL_CAN_READ;
                  if not(__WSAFDIsSet(fd, wfd)) then
                     revents :=revents and not POLL_CAN_WRITE;
                  if not(__WSAFDIsSet(fd, efd)) then
                     revents :=revents and not POLL_HAS_EXCP;
             end;
             fds.revents := revents;
             if (fds.revents <> 0) then
                inc(count);
        end;
    end;
    result:=count;
end;}
{.$ENDIF}

{------------------------------------------------------------------------------}
{ TMysqlVio }
{------------------------------------------------------------------------------}

////////////////////////////////////////////////////////////////////////////////
// class constructor
constructor TMysqlVio.create;
begin
     inherited create;
     FSd :=-1;
     FHPipe :=-1;
     ffcntl_mode :=0;
     ftype :=VIO_CLOSED;
     flast_error:='';
     flast_errno:=0;
     {$IFDEF HAVE_SSL}
     fssl:=nil;
     fnewcon:=nil;
     {$ENDIF}
end;

////////////////////////////////////////////////////////////////////////////////
// class destructor
destructor TMysqlVio.destroy;
begin
     if (ftype<>VIO_CLOSED)then //if vio open
        vio_close; //close it
     inherited destroy;
end;

////////////////////////////////////////////////////////////////////////////////
// attempt to use fast send
function TMysqlVio.fastsend: longint;
var nodelay,i:longint;
begin
     result:=0;
     if (SetSockOpt(fsd, IPPROTO_IP, IP_TOS, i, 0)<>0) then
     begin
          nodelay:=1;
          if (setsockopt(fsd, IPPROTO_TCP, TCP_NODELAY, nodelay,sizeof(nodelay)))<>0 then
             result:= -1;
     end;
end;

////////////////////////////////////////////////////////////////////////////////
// get last error text value
function TMysqlVio.Getlast_error: string;
begin
     result:=Flast_error;
end;

////////////////////////////////////////////////////////////////////////////////
// sets/resets keepalive on socket
function TMysqlVio.keepalive(onoff: boolean): longint;
var opt:longint;
begin
     if (ftype <> VIO_CLOSED) then //is vio connected?
     begin
     result:=0;
     opt:=0;
     if (ftype <> VIO_TYPE_NAMEDPIPE) then
     begin
          if (onoff) then
             opt:=1;
          result:=setsockopt(fsd, SOL_SOCKET, SO_KEEPALIVE, opt, sizeof(opt));
     end;
     end
     else //vio not connected
         result:=-1;
end;

{$IFDEF HAVE_SSL}
////////////////////////////////////////////////////////////////////////////////
// attempt to create a ssl connector
function TMysqlVio.new_VioSSLConnectorFd(const key, cert, ca, capath,
  cipher: pchar): pointer;
var ptr:^st_VioSSLConnectorFd;
    dh:pointer;
begin
     result:=nil;
     new(ptr);
     ptr.ssl_context_:=nil;
     ptr.ssl_method_:=nil;
     //do we have the algorithms loaded?
     if not(ssl_algorithms_added) then
     begin
          ssl_algorithms_added := TRUE;
          OpenSSL_add_all_algorithms; //load them
     end;
     //do we have the error strings?
     if not(ssl_error_strings_loaded)then
     begin
          ssl_error_strings_loaded := TRUE;
          SSL_load_error_strings; //load them
     end;
     ptr.ssl_method_ := TLSv1_client_method; //get the methods
     ptr.ssl_context_ := SSL_CTX_new(ptr.ssl_method_); //get the context
     if (ptr.ssl_context_ = nil) then //empty contex?
     begin
          dispose(ptr);
          exit;
     end;
     if (cipher<>nil)then //did we passed any ciphers?
        SSL_CTX_set_cipher_list(ptr.ssl_context_, cipher);
     //let's check the context
     SSL_CTX_set_verify(ptr.ssl_context_, 1{SSL_VERIFY_PEER}, addr(vio_verify_callback));
     //set the cert stuff
     if (vio_set_cert_stuff(ptr.ssl_context_, cert, key) = -1) then
     begin
          dispose(ptr);
          exit;
     end;
     //verify the locations
     if (SSL_CTX_load_verify_locations( ptr.ssl_context_, ca,capath)=0) then
        if (SSL_CTX_set_default_verify_paths(ptr.ssl_context_)=0) then
        begin
             dispose(ptr);
             exit;
        end;
     //get a new dh
     dh:=get_dh512;
     //check it
     SSL_CTX_ctrl(ptr.ssl_context_,3{SSL_CTRL_SET_TMP_DH},0,dh);
     DH_free(dh);
     result:=ptr;
end;
{$ENDIF}

////////////////////////////////////////////////////////////////////////////////
// set last error text value
procedure TMysqlVio.Setlast_error(const Value: string);
begin
     Flast_error := Value;
end;

{$IFDEF HAVE_SSL}
////////////////////////////////////////////////////////////////////////////////
// attempt to use ssl
procedure TMysqlVio.SwitchToSSL(const key:pchar;const cert:pchar;const ca:pchar;const capath:pchar;var cipher:pchar; timeout:cardinal);
var newcon:^st_VioSSLConnectorFd;
    l:longint;
    server_cert:pointer;
    s:string;
begin
     //are we connected? or are we using named pipe?
     if (ftype<>VIO_CLOSED) and (ftype<>VIO_TYPE_NAMEDPIPE) then
     begin
          //grab a connector
          if cipher='' then
             newcon:= new_VioSSLConnectorFd(key, cert, ca, capath, cipher)
          else
              newcon:= new_VioSSLConnectorFd(key, cert, ca, capath, nil);
          fnewcon:=newcon;
          //new ssl
          fssl := SSL_new(st_VioSSLConnectorFd(newcon^).ssl_context_);
          if (fssl=nil) then
          begin //errors?
               dispose(newcon);
               fnewcon:=nil;
               exit;
          end;
          ftype:=VIO_CLOSED;
          SSL_clear(fssl);
          vio_blocking(FALSE);
          SSL_SESSION_set_timeout(SSL_get_session(fssl), timeout);
          SSL_set_fd (fssl, fsd);
          SSL_set_connect_state(fssl);
          l:=SSL_do_handshake(fssl); //if any of the previous fails this will fail
          if l=1 then
          begin //success
               ftype:=VIO_TYPE_SSL;
               fastsend; //attempt to use fastsend
               keepalive(TRUE);
               cipher:=SSL_CIPHER_get_name(SSL_get_current_cipher(fssl));
               //now we can do some checking on server
               server_cert := SSL_get_peer_certificate (fssl);
               if (server_cert <> nil) then
               begin
                    s := X509_NAME_oneline (X509_get_subject_name (server_cert), nil, 0);
                    //showmessage('info subject: '+ s);

                    s := X509_NAME_oneline (X509_get_issuer_name  (server_cert), nil, 0);
                    //showmessage('info issuer: '+ s);

                    // We could do all sorts of certificate verification stuff here before deallocating the certificate. */
                    X509_free (server_cert);
               end
               else
                   //showmessage('info Server does not have certificate.');
                   ;
          end
          else
          begin //we had errors ... let's clean it
               SSL_shutdown(fssl);
               SSL_free(fssl);
               if fnewcon<>nil then
                  dispose(fnewcon);
               fssl:= nil;
          end;
     end;
end;
{$ENDIF}

////////////////////////////////////////////////////////////////////////////////
// checks whenever vio is blocking
function TMysqlVio.vio_blocking(onoff: boolean): longint;
var r:longint;
    arg:cardinal;
    old_fcntl:longint;
begin
     if (ftype <> VIO_CLOSED) then //is vio connected?
     begin
     r:=0;
     {$IFNDEF asl}  //_WIN_} //if it is on linux
     if (fsd >= 0) then
     begin
          old_fcntl:=ffcntl_mode;
          if (onoff) then
             ffcntl_mode :=ffcntl_mode and ($7FFFFFFE)
          else
              ffcntl_mode := ffcntl_mode or 1;
          if (old_fcntl <> ffcntl_mode) then
             r := fcntl(fsd, F_SETFL, ffcntl_mode);
     end;
     {$ELSE} //if it is not on linux
     if (ftype <> VIO_TYPE_NAMEDPIPE) then //pipes don't need blocking
     begin
          old_fcntl:=ffcntl_mode;
          if (onoff) then
          begin //set blocking
               arg := 0;
               ffcntl_mode := ffcntl_mode and $7FFFFFFE
          end
          else
          begin //reset blocking
               arg := 1;
               ffcntl_mode := ffcntl_mode or 1;
          end;
          if (old_fcntl<>ffcntl_mode) then
             r:=OS2Socket.ioctl(fsd,cardinal(FIONBIO), longint(arg), 4);
     end;
     {$ENDIF}
     result:=r;
     end
     else //vio not connected
         result:=-1;
end;

////////////////////////////////////////////////////////////////////////////////
// closes the socket/pipe
function TMysqlVio.vio_close: longint;
begin
     result:=0;
     {$IFDEF HAVE_SSL}
     if assigned(fssl) then
     begin //did we used ssl?
          //free it
          result := SSL_shutdown(fssl);
          SSL_free(fssl);
          if fnewcon<>nil then
             dispose(fnewcon);
          fssl:= nil;
     end;
     {$ENDIF}
{$IFDEF _WIN_}
     if (ftype=VIO_TYPE_NAMEDPIPE) then
        result:=longint(CloseHandle(fhPipe))
     else
{$ENDIF}
         if (ftype <> VIO_CLOSED) then
         begin
              result:=0;
              if (shutdown(fsd,2)<>0) then
                 result:=-1;
              {$IFDEF _WIN_}
              if (closesocket(fsd)<>0) then
                 result:=-1;
              {$ENDIF}
         end;
     ftype:=VIO_CLOSED;
     fsd:=-1;
     FHPipe:=-1;
     ffcntl_mode:=0;
end;

////////////////////////////////////////////////////////////////////////////////
// checks whenever the communication was intrerupted
function TMysqlVio.vio_intrerupted: boolean;
begin
     {$IFDEF _WIN_}
     result:=WSAGetLastError = WSAEINTR;
     {$ELSE}
     result:=sock_errno = EINTR;
     {$ENDIF}
end;

////////////////////////////////////////////////////////////////////////////////
// main vio function it creates the pipe, connects the socket
// will return -x on error ??
// _type represent the kind of vio we open (ssl not supported on connect in this version)
// host and unix_socket are obvious
// connect_timeout is used only on named pipes
// trysock is used when you try a pipe and if in error you want to try socket
function TMysqlVio.vio_open( _type:TEnumVioType; host:string; unix_socket:string; port:longint; connect_timeout:cardinal; trysock:boolean): longint;
var hPipe:longint;
    sock:longint;
    sock_addr:SockAddr_in;
//    ip_addr:cardinal;
    hp:phostent;
    arg:cardinal;
    lhost:string; //store temp values
    lunix_socket:string; //store temp values
    szPipeName:string[255];
    i:integer;
    dwMode:cardinal;
begin
     if ftype=VIO_CLOSED then
     begin
     if _type=VIO_TYPE_SSL then
     begin
          result:=-2; //ssl not supported yet
          exit;
     end;
     //only if using winsock
     {$IFDEF _WIN_}
     if (_type = VIO_TYPE_TCPIP)or(trysock) then //do we need winsock?
        if fWsaData.wVersion=0 then // has it been initialized before
           if (WSAStartup ($0101, fWsaData)<>0) then
              begin
                   result:=-1; //we can't start winsock - one should never get here
                   exit;
              end;
     {$ENDIF}
     hpipe:=INVALID_HANDLE_VALUE;
     lhost:=host;
     lunix_socket:=unix_socket;
     sock := SOCKET_ERROR;
     {$IFDEF _WIN_}
     if (_type = VIO_TYPE_NAMEDPIPE) then
     begin
          //one may pass wrong host info
          if (host='') or (host<>LOCAL_HOST_NAMEDPIPE) then
             host:=LOCAL_HOST_NAMEDPIPE;
          if (unix_socket='') or (unix_socket<>MYSQL_NAMEDPIPE) then
             unix_socket:=MYSQL_NAMEDPIPE;
     end;
     if (_type = VIO_TYPE_NAMEDPIPE) and
        (((host<>'') and (host=LOCAL_HOST_NAMEDPIPE))or
        ((unix_socket<>'') and(unix_socket=MYSQL_NAMEDPIPE)))
        then //we try a named pipe
     begin
          szPipeName:='\\'+host+'\pipe\'+unix_socket;
          for i:=0 to 100 do //try 100 times to connect - one may remove this
          begin
               //try open the pipe
               hPipe := CreateFile(pchar(longint(@szPipeName)+1),
                        cardinal(GENERIC_READ or GENERIC_WRITE),
                        0,nil,OPEN_EXISTING,0,0 );
               if ( hPipe<> INVALID_HANDLE_VALUE) then //success?
                  break;
               if (GetLastError <> ERROR_PIPE_BUSY) then //we got another error than pipe busy?
               begin
                    //we can stop trying
                    flast_errno:=CR_NAMEDPIPEOPEN_ERROR;
                    flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[host, unix_socket,GetLastError]);
                    if not trysock then //should we try socket?
                    begin
                         result:=-9;
                         exit;
                    end
                    else
                        break;
               end;
               //let's wait for a while .. maybe the pipe will not be busy
               if (not WaitNamedPipe(pchar(longint(@szPipeName)+1), connect_timeout*1000) )then
               begin
                    flast_errno:=CR_NAMEDPIPEWAIT_ERROR;
                    flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[host,unix_socket,GetLastError]);
                    if not trysock then //should we try socket?
                    begin
                         result:=-9;
                         exit;
                    end
                    else
                        break;
               end;
          end;
          //we just tryed 100 times .. still not there?
          if (hPipe = INVALID_HANDLE_VALUE) then
          begin
               flast_errno:=CR_NAMEDPIPEOPEN_ERROR;
               flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[host,unix_socket,GetLastError]);
               if not trysock then //should we try socket?
                  begin
                       result:=-9;
                       exit;
                  end;
          end;
          if hPipe<>INVALID_HANDLE_VALUE then //are we connected or just wait to try socket
          begin
          dwMode := PIPE_READMODE_BYTE or PIPE_WAIT;
          if ( not SetNamedPipeHandleState(hPipe, dwMode, nil, nil) ) then //set up pipe for reading
          begin
               //we can't set it up .. there must be something wrong
               //we can close the pipe
               CloseHandle( hPipe );
               hPipe:=INVALID_HANDLE_VALUE;
               flast_errno:=CR_NAMEDPIPESETSTATE_ERROR;
               flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[host, unix_socket,GetLastError]);
               if not trysock then //should we try socket?
                  begin
                       result:=-9;
                       exit;
                  end;
          end;
          end;
          if (hPipe=INVALID_HANDLE_VALUE) then //all that work .. and we failed to create the pipe
          begin
               if not trysock then //should we try socket?
                  begin
                       result:=-9;
                       exit;
                  end;
          end
          else
          begin //we created the pipe ... yesss!!!
               ftype:=VIO_TYPE_NAMEDPIPE;
               fsd:=0;
               fhPipe:=hPipe;
               result:=0;
               exit;
          end;
     end;
     if ((hPipe = INVALID_HANDLE_VALUE)and (_type=VIO_TYPE_NAMEDPIPE))or(trysock) then //only if we failed creating the pipe and we can try sockets
     {$ENDIF}
     begin
          //restore values if we cahnged them trying the pipe
          host:=lhost;
          unix_socket:=lunix_socket;
          if (port=0)then
             port:=mysql_port;
          if (host='') then
             host:='localhost';
          sock := socket(AF_INET,SOCK_STREAM,0); //try grab a socket
          if (sock = SOCKET_ERROR) then //error?
          begin
               flast_errno:=CR_IPSOCK_ERROR;
               {$IFDEF _WIN_}
               flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[WSAGetLastError]);
               {$ELSE}
               flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[sock_errno]);
               {$ENDIF}
               result:=-8;//we failed the socket creation
               exit;
          end;
          {$IFNDEF asl}
          ffcntl_mode := fcntl(fsd, F_GETFL);
          {$ENDIF}
          arg:=0;
          {$IFDEF _WIN_}
          ioctlsocket(fsd,cardinal(FIONBIO),longint(arg));
          {$ENDIF}
          //try to resolve the host
          fillchar(sock_addr,sizeof(sock_addr),#0);
          sock_addr.sin_family := AF_INET;
          sock_addr.sin_addr.s_addr:=SockInetAddr(host);
//          ip_addr := inet_addr(@host[1]);
          if (sock_addr.sin_addr.s_addr = INADDR_NONE) then
          begin
               hp:=gethostbyname(pchar(@host[1]));
               if (hp=nil) then
               begin
                    flast_errno:=CR_UNKNOWN_HOST;
                    {$IFDEF _WIN_}
                    flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[host, WSAGetLastError]);
                    {$ELSE}
                    flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR],[host, sock_errno]);
                    {$ENDIF}
                    result:=-7; //we can't connect
                    exit;
               end;
//               ip_addr:=byte(hp^.h_addr^)+(byte(hp^.h_addr^)shl 8)+(byte(hp^.h_addr^)shl 16)+(byte(hp^.h_addr^)shl 24);
//               sock_addr.sin_addr:=in_addr(ip_addr);
               sock_addr.sin_addr:=hp^.h_addr^^;
               hp^.h_length:=10;
          end;
          //sock_addr.sin_port := port;
          sock_addr.sin_port := htons(port);
          //we resolved the address .. let's try to connect
          if (connect(sock,SockAddr(sock_addr), sizeof(tsockaddr)) <0) then
          begin
               flast_errno:= CR_CONN_HOST_ERROR;
               {$IFDEF _WIN_}
               flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR], [host, WSAGetLastError]);
               {$ELSE}
               flast_error:=format(client_errors[(flast_errno)-CR_MIN_ERROR], [host, sock_errno]);
               {$ENDIF}
               result:=-6; //we can't connect
               exit;
          end;
     end;
     if ftype<>VIO_TYPE_NAMEDPIPE then
        fastsend; //attempt to use fastsend
     keepalive(TRUE);
     ftype:=VIO_TYPE_TCPIP;
     fsd:=sock;
     fhPipe:=0;
     result:=0;//no errors and we are connected (we can start talking to the server)
     flast_error:='';
     flast_errno:=0;
     end
     else //vio allready open
         result:=-20;
end;

////////////////////////////////////////////////////////////////////////////////
// poll read via select
// waits a specific interval to read something
function TMysqlVio.vio_poll_read(timeout: cardinal): boolean;
var fds:TPollFD;
    res:longint;
    Bytes: LongInt;
begin
     if (ftype = VIO_TYPE_NAMEDPIPE) then
     begin
          result:=true;
          exit;
     end;
     if (ftype <> VIO_CLOSED) then //is vio connected?
     begin
     fds.fd:=fsd;
     fds.events:=POLLIN;
     fds.revents:=0;
//     res:=poll({$IFNDEF _WIN_}@{$ENDIF}fds,{$IFNDEF _WIN_}1,{$ENDIF}timeout*1000);
     res:=os2Socket.IOCtl(fsd,FIONRead, Bytes, SizeOf(Bytes));
     if res<0 then
        result:=false //don't return true on errors
     else
         if res=0 then
            result:=true
         else
         if fds.revents AND POLLIN = POLLIN then
            result:=false
         else
              result:=true;
     end
     else //vio is not connected return false
         result:=false;
end;

////////////////////////////////////////////////////////////////////////////////
// reads "size" bytes into a buffer "buf" from socket/pipe
function TMysqlVio.vio_read(buf: pointer; const sz: Integer): longint;
var len1:cardinal;
begin
     if (ftype <> VIO_CLOSED) then //vio is connected we can receive
     begin
          {$IFDEF HAVE_SSL}
          if (ftype =VIO_TYPE_SSL) then //if vio is ssl
          begin
               //errno = 0;
               result := SSL_read(fssl, buf^, sz);
               if ( result<= 0) then
                  result:=- SSL_get_error(fssl, result); //- because the errors are positive and it may look as we send "errno" bytes
               exit;
          end;
          {$ENDIF}
     {$IFDEF _WIN_}
     //extra check since in windows we can use pipes rather than sockets
     if (ftype = VIO_TYPE_NAMEDPIPE)then
     begin
          //if it is pipe we read from it
          if not(ReadFile(fhPipe, buf^, sz, len1, nil)) then
             result:=-1
          else
              result:=len1;
     end
     else //we read via socket
         result:=recv(fsd, buf^, sz,0);
     {$ELSE}
     //we don't have pipes on linux .. so just read from socket
//     errno:=0;
     result := recv(fsd, buf^, sz,0);
     {$ENDIF}
     end
     else //vio not connected returns -1
         result:=-1;
end;

////////////////////////////////////////////////////////////////////////////////
// returns true if we should try again to read/write
function TMysqlVio.vio_should_retry: boolean;
var en:longint;
begin
     if (ftype <> VIO_CLOSED) then //vio is connected
     begin
     //get last error
     {$IFDEF _WIN_}
     en:=WSAGetLastError;
     {$ELSE}
     en:=sock_errno;
     {$ENDIF}
     //check if we should retry
     {$IFDEF _WIN_}
     result:= (en=WSAEINPROGRESS)or(en=WSAEINTR)or(en=WSAEWOULDBLOCK);
     {$ELSE}
     result:= (en = EAGAIN) or (en = EINTR);
     {$ENDIF}
     end
     else //vio is not connected .. no point to retry
         result:=false;
end;

////////////////////////////////////////////////////////////////////////////////
// writes "size" bytes from a buffer "buf" to socket/pipe
function TMysqlVio.vio_write(buf: pointer; size: Integer): longint;
var len1:cardinal;
begin
     if (ftype <> VIO_CLOSED) then //if vio is connected
     begin
          {$IFDEF HAVE_SSL}
          if (ftype =VIO_TYPE_SSL) then //if vio is ssl
          begin
               result := SSL_write(fssl, pchar(buf^)^, size);
               exit;
          end;
          {$ENDIF}
     {$IFDEF _WIN_}
     //extra check since in windows we can use pipes rather than sockets
     if (ftype = VIO_TYPE_NAMEDPIPE) then
     begin
          //if it is pipe we write into it
          if not(WriteFile(fhPipe, pchar(buf^)^, size, len1, nil)) then
             result:=-1
          else
              result:=len1;
     end
     else //we send via socket
         result:=send(fsd, pchar(buf^)^, size,0);
     {$ELSE}
     //we don't have pipes on linux .. so just write to socket
//     errno:=0;
     result := send(fsd, pchar(buf^)^, size,0);
     {$ENDIF}
     end
     else //vio not connected returns -1 allways
         result:=-1;
end;

////////////////////////////////////////////////////////////////////////////////
// set wVersion to 0 as initial value
// any other value in finalization will call WSACleanup
// Note: only for windows
initialization
begin
      {$IFDEF _WIN_}
     fWsaData.wVersion:=0;
     {$ENDIF}
end;

////////////////////////////////////////////////////////////////////////////////
// if wVersion is <> 0 we need to clean winsock
// Note: only for windows
finalization
begin
     {$IFDEF _WIN_}
     if fWsaData.wVersion<>0 then
        WSACleanup;
     {$ENDIF}
end;

end.
