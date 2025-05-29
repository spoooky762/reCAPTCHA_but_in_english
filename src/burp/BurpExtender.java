package burp;

import java.awt.Component;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

import javax.swing.JMenuItem;

import custom.GUI;
import custom.ImageHandler;

public class BurpExtender extends GUI implements IBurpExtender, ITab, IContextMenuFactory, 
IIntruderPayloadGeneratorFactory,IIntruderPayloadGenerator,IExtensionStateListener
{	
	private static IBurpExtenderCallbacks callbacks;
	private static IExtensionHelpers helpers;

	public static PrintWriter stdout;
	public static PrintWriter stderr;

	IMessageEditor imageMessageEditor;
	public static Config config;
	
	@Override
	public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
	{
		BurpExtender.callbacks = callbacks;
		helpers = callbacks.getHelpers();
		flushStd();
		stdout.println(Info.getFullExtensionName());
		stdout.println(Info.github);
		callbacks.setExtensionName(Info.getFullExtensionName()); //Plugin name
//callbacks.registerHttpListener(this); //If there is no registration, the following processHttpMessage method will not take effect. Plugins for handling request and response packages, this should be necessary
		callbacks.registerContextMenuFactory(this);
		callbacks.registerIntruderPayloadGeneratorFactory(this);
		callbacks.addSuiteTab(BurpExtender.this);
		config = Config.LoadConfigFromBurp();
	}
	
	

	private static void flushStd(){
		try{
			stdout = new PrintWriter(callbacks.getStdout(), true);
			stderr = new PrintWriter(callbacks.getStderr(), true);
		}catch (Exception e){
			stdout = new PrintWriter(System.out, true);
			stderr = new PrintWriter(System.out, true);
		}
	}

	/////////////////////////////////////////Custom functions/////////////////////////////////////////////////////////////
	public static IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}

	public String getHost(IRequestInfo analyzeRequest){
		List<String> headers = analyzeRequest.getHeaders();
		String domain = "";
		for(String item:headers){
			if (item.toLowerCase().contains("host")){
				domain = new String(item.substring(6));
			}
		}
		return domain ;
	}

	public static String getImage(Config config) {
		if (config == null) {
			return null;
		}
		try {
			IHttpService service = config.getHttpService();
			byte[] request =  config.getRequestBytes();
			if (GUI.rdbtnUseSelfApi.isSelected()) {
				String proxy = GUI.proxyUrl.getText().trim();
				return ImageHandler.download(service, request, proxy);
			}else {
				return ImageHandler.downloadWithBurpMethod(service,request);
			}
		} catch (Exception e) {
			e.printStackTrace(stderr);
			return null;
		}
	}

	///////////////////////////////////////////////////////Custom functions////////////////////////////////////////////////

/////////////////////////////////////////The following are the necessary methods for burp --start////////////////

	//Two methods that ITab must implement
	@Override
	public String getTabCaption() {
		return ("reCAPTCHA");
	}
	@Override
	public Component getUiComponent() {
		return this.getContentPane();
	}
	public BurpExtender getThis() {
		return this;
	}

	@Override
	public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation)
	{ //Register with signature! ! callbacks.registerContextMenuFactory(this);
		IHttpRequestResponse[] messages = invocation.getSelectedMessages();
		List<JMenuItem> list = new ArrayList<JMenuItem>();
		if((messages != null) && (messages.length ==1))
		{	
			IHttpRequestResponse imgMessageInfo = messages[0];
			
			config.setRequestBytes(imgMessageInfo.getRequest());
			config.setHost(imgMessageInfo.getHttpService().getHost());
			config.setPort(imgMessageInfo.getHttpService().getPort());
			config.setProtocol(imgMessageInfo.getHttpService().getProtocol());
			config.saveConfigToBurp();

			JMenuItem menuItem = new JMenuItem("Send to reCAPTCHA");
			menuItem.addActionListener(new ActionListener()
			{
				public void actionPerformed(ActionEvent e)
				{
					try
					{	
						showMessage();
					}
					catch (Exception e1)
					{
						e1.printStackTrace(stderr);
					}
				}
			});
			list.add(menuItem);
		}
		return list;
	}
	
	public static void showMessage() {
		imgRequestRaws.setText(new String(config.getRequestBytes())); //Show this request information in the GUI.
		imgHttpService.setText(config.getHttpService().toString());
	}


	//IIintruderPayloadGeneratorFactory 2 functions required to implement
	@Override
	public String getGeneratorName() {
		return "reCAPTCHA";
	}

	@Override
	public IIntruderPayloadGenerator createNewInstance(IIntruderAttack attack) {

		return this;
	}


	//IIIntruderPayloadGenerator three functions required to implement
	@Override
	public boolean hasMorePayloads() {
		return true;
	}

	@Override
	public byte[] getNextPayload(byte[] baseValue) {
		// Get the value of the image verification code
		int times = 0;
		while(times <=5) {
			if (config!=null) {
				try {	
					
				//String imgpath = imageDownloader.download(callbacks, helpers, imgMessageInfo.getHttpService(), imgMessageInfo.getRequest());
				String imgpath = BurpExtender.getImage(config);
				String code = getAnswer(imgpath).trim(); //The verification code trim should not have any problems
				stdout.println(imgpath+" --- "+code);
				return code.getBytes();
			} catch (Exception e) {
				e.printStackTrace(stderr);
				return e.getMessage().getBytes();
			}
		}else {
				stdout.println("Failed try!!! please send image request to reCAPTCHA first!");
				times +=1;
				continue;
			}
		}
		return null;
	}
	
	@Override
	public void reset() {

	}



	@Override
	public void extensionUnloaded() {
		config.saveConfigToBurp();
	}

	////////////////////////////////////////////// Various burp-essential methods --end//////////////////////////////////////////////////////////////
}
