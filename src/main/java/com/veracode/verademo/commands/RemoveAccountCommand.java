package com.veracode.verademo.commands;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;

public class RemoveAccountCommand implements BlabberCommand {
	private static final Logger logger = LogManager.getLogger("VeraDemo:RemoveAccountCommand");
	
	private Connection connect;
	
	public RemoveAccountCommand(Connection connect, String username) {
		super();
		this.connect = connect;
	}

	/* (non-Javadoc)
	 * @see com.veracode.verademo.commands.Command#execute()
	 */
	@Override
	public void execute(String blabberUsername) {
		String sqlQuery = "DELETE FROM listeners WHERE blabber=? OR listener=?;";
		logger.info(sqlQuery);
		PreparedStatement action;
		try {
			action = connect.prepareStatement(sqlQuery);
			
			action.setString(1, blabberUsername);
			action.setString(2, blabberUsername);
			action.execute();

			Statement sqlStatement = connect.createStatement();
sqlQuery = "SELECT blab_name FROM users WHERE username = ?";
PreparedStatement sqlStatement2 = connect.prepareStatement(sqlQuery);
sqlStatement2.setString(1, blabberUsername);
logger.info(sqlQuery);
ResultSet result = sqlStatement2.executeQuery();
			result.next();
			
			/* START BAD CODE ------*/
			String event = "Removed account for blabber " + result.getString(1);
			sqlQuery = "INSERT INTO users_history (blabber, event) VALUES ('" + blabberUsername + "', '" + event + "')";
			logger.info(sqlQuery);
			sqlStatement.execute(sqlQuery);
			
			sqlQuery = "DELETE FROM users WHERE username = '" + blabberUsername + "'";
			logger.info(sqlQuery);
PreparedStatement sqlStatement2 = connect.prepareStatement("DELETE FROM users WHERE username = ?");
sqlStatement2.setString(1, blabberUsername);
sqlStatement2.execute();
			/* END BAD CODE */
			
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
}
