program VirusTotalUploader;

{$APPTYPE CONSOLE}
{$R *.res}

(*
  Projeto original: https://github.com/ms301/VirusTotal.git 22/03/2016
*)

uses
  System.SysUtils,
  Winapi.Windows,
  Vcl.Forms,
  VirusTotal in 'VirusTotal.pas',
  XSuperObject in 'XSuperObject.pas',
  XSuperJSON in 'XSuperJSON.pas',
  auxiliares in 'auxiliares.pas';

const
  VERSAO        = '1.0.0';  //Para novas releases altere a versão
  APIKEY        = '6dfa2c6d7241c2815faacdc0ca935f1a35af1a181c8ff4585f04fbe13a8c53d0'; //Chave publica do virus total
var
  aFileName     : string;
  virusTotal    : TVirusTotalAPI;
  vtFileSend    : TvtFileSend;
  vtFileReport  : TvtFileReport;
  i, j          : Integer;
  codExit       : Byte;

const
  SEPARADOR = '==========================';

procedure verificarFalsoPositivo(antiVirus:string; result:string);
begin
  if result <> '' then
    begin
      Inc(codExit);
      Writeln('DETECTADO:   ' + AnsiUpperCase(antiVirus) + ': ', AnsiUpperCase(result));
    end;
end;

function getArquivoTeste():string;
begin
  Result := Application.ExeName + '_vt';
end;

begin
  codExit := 0;

  if ParamStr(1) = '' then
    begin
      CopyFile(PWideChar(Application.ExeName), PWideChar(getArquivoTeste()), True);
      aFileName := getArquivoTeste();
    end
  else
    aFileName := ParamStr(1);

  virusTotal        := TVirusTotalAPI.Create;
  virusTotal.ApiKey := APIKEY;
  try
    try
      Writeln(SEPARADOR + ' VIRUS-TOTAL UPLOADER ' + SEPARADOR);
      Writeln('VERSAO:      ' + VERSAO);
      Writeln('APIKEY:      ' + APIKEY);
      Writeln('ENVIANDO:    ' + aFileName);
      vtFileReport := virusTotal.reportFile(GetFileHashMD5(aFileName));

      if vtFileReport.response_code = 0 then //Verifica se arquivo ja foi enviado
        vtFileSend := virusTotal.ScanFile(aFileName);

      for i := 0 to 4 do
        begin
          if vtFileReport.response_code = 1 then
            Break;
          Writeln('VERIFICACAO: ', 'O SERVICO ONLINE ESTÁ EXAMINANDO O ARQUIVO - (', i + 1, '/4).'); //vtFileReport.verbose_msg
          Write('STATUS:      AINDA AGUARDANDO RESPOSTA DO EXAME');
          vtFileReport := virusTotal.reportFile(vtFileSend.md5);
          for j := 0 to 5 do
            begin
              Write('.');
              Sleep(10000);
            end;
          WriteLn('');
        end;

      if vtFileReport.response_code = 1 then
        begin
          verificarFalsoPositivo('Kaspersky',     vtFileReport.scans.Kaspersky.result);
          verificarFalsoPositivo('AVG',           vtFileReport.scans.AVG.result);
          verificarFalsoPositivo('Avast',         vtFileReport.scans.Avast.result);
          verificarFalsoPositivo('Avira',         vtFileReport.scans.Avira.result);
          verificarFalsoPositivo('BitDefender',   vtFileReport.scans.BitDefender.result);
          verificarFalsoPositivo('Eset_Nod32',    vtFileReport.scans.ESET_NOD32.result);
          verificarFalsoPositivo('Comodo',        vtFileReport.scans.Comodo.result);
          verificarFalsoPositivo('ClamAV',        vtFileReport.scans.ClamAV.result);
          verificarFalsoPositivo('Malwarebytes',  vtFileReport.scans.Malwarebytes.result);
          verificarFalsoPositivo('McAfee',        vtFileReport.scans.McAfee.result);
          verificarFalsoPositivo('TrendMicro',    vtFileReport.scans.TrendMicro.result);
          verificarFalsoPositivo('Microsoft',     vtFileReport.scans.Microsoft.result);
          verificarFalsoPositivo('Panda',         vtFileReport.scans.Panda.result);
          verificarFalsoPositivo('Symantec',      vtFileReport.scans.Symantec.result);
          verificarFalsoPositivo('AegisLaba',        vtFileReport.scans.AegisLab.result);
        end
      else
        Writeln('FALHA NA VERIFICAÇÃO DO ARQUIVO!');

      if codExit > 0 then
        begin
          Writeln('RESUMO:      FOI DETECTADO VÍRUS NO ARQUIVO EXAMINADO!');
          Writeln('OBSERVAÇÃO:  VERIFIQUE-O MANUALMENTE POIS PODE SE TRATAR DE UM FALSO POSITIVO.');
        end
      else
        Writeln('RESUMO:      NÃO FOI DETECTADO VIRUS NO ARQUIVO EXAMINADO!' );

    except
      on E: Exception do Writeln(E.ClassName, ': ', E.Message);
    end;

  finally
    FreeAndNil(virusTotal);
  end;

  if AnsiUpperCase(ParamStr(2)) =  '/NOHALT' then
    codExit := 0;

  Halt(codExit);

end.
