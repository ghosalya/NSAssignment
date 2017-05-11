
import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.util.concurrent.*;
import java.net.InetAddress;

public class NSAssignmentGUI extends JFrame {
	
	//client side
	private JTextField IPAddressTF, FilePathTF; 
	private JButton changeToServerButton, ChooseFileButton, SendFileButton;
	private JLabel statusLabel;
	
	//server side
	private JLabel IPAddressLabel, serverStatusLabel;
	private JButton startServerButton, changeToClientButton;
	private JTextField downloadPathTF;
	
	
	private Executor exec = Executors.newFixedThreadPool(4);
	
	public NSAssignmentGUI() {
		createClientView();
		setSize(new Dimension(500,400));
		//pack(); //use before setLocationRelativeTo
		setLocationRelativeTo(null);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setTitle("NSAssignment - File Transfer");
		setResizable(false);
		//invoke setVisible() only after creating, from outside
	}
	
	private JPanel createServerView() {
		JPanel panel = new JPanel();
		getContentPane().add(panel);
		
		String ipp = "IP Not found";
		
		try {
			ipp = InetAddress.getLocalHost().toString();
		} catch (Exception e) {}
		
		IPAddressLabel = new JLabel(ipp);
		panel.add(IPAddressLabel);
		
		if(startServerButton==null) {
			startServerButton = new JButton("Start Server");
			startServerButton.addActionListener(new StartServerActionListener());
		}
		panel.add(startServerButton);
		
		if(changeToClientButton==null) {
			changeToClientButton = new JButton("to Client Mode");
			changeToClientButton.addActionListener(new ChangeToClientActionListener());
		}
		panel.add(changeToClientButton);
		
		getContentPane().add(panel);
		return panel;
	}
	
	private JPanel createClientView() {
		JPanel panel = new JPanel();
		getContentPane().add(panel);
		
		if(IPAddressTF == null) {
			IPAddressTF = new JTextField();
			IPAddressTF.setPreferredSize(new Dimension(200, 25));
		}
		panel.add(IPAddressTF);
		
		if(FilePathTF==null) {
			FilePathTF = new JTextField();
			FilePathTF.setPreferredSize(new Dimension(400, 25));
		}
		panel.add(FilePathTF);
		
		if(SendFileButton==null) {
			SendFileButton = new JButton("Send");
			SendFileButton.addActionListener( new SendFileActionListener());
		}
		panel.add(SendFileButton);
		
		if(statusLabel==null) {
			statusLabel = new JLabel("Jackspedicy");
		}
		panel.add(statusLabel);
		
		if(changeToServerButton==null) {
			changeToServerButton = new JButton("to Server Mode");
			changeToServerButton.addActionListener(new ChangeToServerActionListener());
		}
		panel.add(changeToServerButton);
		
		getContentPane().add(panel);
		return panel;
		
	}
	
	public static void main(String[] args) {
		new NSAssignmentGUI().setVisible(true);
	}
	
	private class StartServerActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			//whenever button is clicked
			
			exec.execute(new Runnable() {
				@Override
				public void run() {
					try{
						SecStore serv = new SecStore();
						serv.attemptServerVerification();
					} catch (Exception e) {}
					
				}
			});
		}
	}
	
	private class SendFileActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			//whenever button is clicked
			String ipaddress = IPAddressTF.getText();
			String filepath = FilePathTF.getText();
			
			if(!Client.checkValidIPAddress(ipaddress)) return;
			File file=Crypto.getFile(filepath);
			if((file) == null) return;
			
			exec.execute(new Runnable() {
				@Override
				public void run() {
					Client.clientHandleFile(ipaddress, file);
				}
			});
		}
	}
	
	private class ChangeToClientActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			setVisible(false);
			getContentPane().removeAll();
			createClientView();
			setVisible(true);
		}
	}
	
	private class ChangeToServerActionListener implements ActionListener {
		@Override
		public void actionPerformed(ActionEvent e) {
			setVisible(false);
			getContentPane().removeAll();
			createServerView();
			setVisible(true);
		}
	}

}