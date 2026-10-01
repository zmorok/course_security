using System.Windows;
using QrAuthenticity.Cutted.Services;
using QrAuthenticity.QR;

namespace QrAuthenticity.Cutted;

public partial class MainWindow : Window
{
    public MainWindow()
    {
        InitializeComponent();
        var payloadService = new EncryptedDocumentService();
        var qrService = new QrCodeService();
        CreationTab.Initialize(payloadService, qrService);
        ReadingTab.Initialize(payloadService, qrService);
        ReadingTab.GetCurrentGeneratedQr = () => CreationTab.CurrentGeneratedQr;
        ReadingTab.GetCurrentGeneratedPayload = () => CreationTab.CurrentQrEncodedPayload;
        CreationTab.CreateQr();
    }
}
