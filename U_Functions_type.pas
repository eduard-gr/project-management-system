unit U_Functions_type;
interface
type
   PMConnectParams = Record
    INHOST       :string;
    INPORT       :Word;
    INUSER       :string;
    INPWD        :string;
    InBDName     :string;
end;

var
ConnectParams : PMConnectParams;

implementation

end.
