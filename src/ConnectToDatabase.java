import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.*;

public class ConnectToDatabase {
    public Connection connect() {

        String MySQLURL = "jdbc:mysql://127.0.0.1:3306/password manager";
        String databseUserName = "root";
        String databasePassword = "";
        Connection con = null;


        try {

                con = DriverManager.getConnection(MySQLURL, databseUserName, databasePassword);

    } catch (Exception e) {
            e.printStackTrace();
        }
        if (con != null) {
            System.out.println("Database connection is successful !!!!");
            return con;


        }
        return null;
    }
    public String username(String name ){
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            try {
                stmt = (Statement) con.createStatement();

                ResultSet user = stmt.executeQuery("SELECT * FROM `user` WHERE name=\""+name+"\" ");
                if(user.next() )
                  return "user name already token";
                else
                    return "available";
            } catch (SQLException throwables) {
                throwables.printStackTrace();
            }
        }
return "error";
            }
    public String Login(String name ,String pass)  {
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            try {
                stmt = (Statement) con.createStatement();

            ResultSet user = stmt.executeQuery("SELECT * FROM `user` WHERE name=\""+name+"\" ");
            //AND password=\""+pass+"\"");
               //boolean truePass= );
               // System.out.println(user.next());
            if(user.next() ) {
            //    System.out.println(pass+"  "+user.getString("password"));
            if(VerifyingPasswords.validatePassword(pass,user.getString("password")))
                return user.getInt("id") + ":  " + user.getString("name");
            else
                return "Wrong Password ";
            }else
                return "user not found ";
                } catch (SQLException throwables) {
                throwables.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }

            return "connection error";
    }
    public String getAllPass(String id){
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            ResultSet pass =null;
            try {
                stmt = (Statement) con.createStatement();

                pass = stmt.executeQuery("SELECT * FROM password WHERE user_id="+id);
                //System.out.println("SELECT * FROM password WHERE user_id="+id);
            }catch (SQLException throwable) {
                throwable.printStackTrace();
            }
            try {
                String passwords="";
                while (pass.next()){
                    passwords+= pass.getInt("id")+" "
                            +pass.getString("address")+" "
                            +pass.getString("password")+" "
                            +pass.getString("email")+" "
                            +pass.getString("hint")+" "
                            +pass.getString("attached")+" | ";}

                    return passwords;
            } catch (SQLException throwable) {
                throwable.printStackTrace();
            }
        }
        return "connection error";
    }


    public String Signup(String name ,String pass) {
        Statement stmt = null;
        Connection con = this.connect();
        String id="-1";
        if (con != null) {
            try {

                String availability=username(name);
                if(!availability.equals("available"))
                    return availability;

                pass= VerifyingPasswords.hash_paa(pass);
                stmt = (Statement) con.createStatement();
                int res= stmt.executeUpdate("INSERT INTO user (name,password) VALUES ( '"+name+"','"+pass+"')",Statement.RETURN_GENERATED_KEYS);
                ResultSet rs = stmt.getGeneratedKeys();
                if (rs.next()){
                    id=rs.getInt(1)+" : "+name;
                }

            }catch (SQLException throwable) {
                throwable.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }
            return id;
        }
        return "connection error";
    }
    public String addPass(String address,String email,String pass,String hint,String attached,String user_id){
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            try {
                stmt = (Statement) con.createStatement();
              //  System.out.println("INSERT INTO password " + "VALUES (3 '"+name+"',"+pass+")");
                stmt.executeUpdate("INSERT INTO password(address,email,password,hint,attached,user_id) " + "VALUES ('"+address+"','"+email+"','"+pass+"','"+hint+"','"+attached+"','"+user_id+"')");
            }catch (SQLException throwable) {
                throwable.printStackTrace();
            }
            return "password added successfully";
        }
        return "connection error";
    }
    public String updatePass(String address,String email,String pass,String hint,String attached,String id,String User_id){
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            try {
                stmt = (Statement) con.createStatement();
                ResultSet Updated_pass = stmt.executeQuery("SELECT * FROM password WHERE id=" +id);
                if(! (Updated_pass.getInt("user_id")+"").equals(User_id))
                    return "not Auth";
                stmt.executeUpdate("UPDATE 'password' set address=\""+address+"\", email=\""+email+"\" , password=\""+pass+"\" , hint=\""+hint+"\" , attached=\""+attached+"\" WHERE id=\""+id+"\"");
            }catch (SQLException throwable) {
                throwable.printStackTrace();
            }
            return "password updated successfully";
        }
        return "connection error";
    }
    public String getPass(String id){
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            ResultSet pass =null;
            try {
                stmt = (Statement) con.createStatement();

                 pass = stmt.executeQuery("SELECT * FROM password WHERE id=" +id);
            }catch (SQLException throwable) {
                throwable.printStackTrace();
            }
            try {
                if(pass.next())
                return pass.getInt("id")+" "
                        +pass.getString("address")+" "
                        +pass.getString("password")+" "
                        +pass.getString("email")+" "
                        +pass.getString("hint")+" "
                        +pass.getString("attached");
                else
                    return "password not found";
            } catch (SQLException throwable) {
                throwable.printStackTrace();
            }
        }
        return "connection error";
    }
    public String deletePass(String id,String user_id){
        Statement stmt = null;
        Connection con = this.connect();
        if (con != null) {
            try {
                stmt = (Statement) con.createStatement();
                ResultSet pass = stmt.executeQuery("SELECT * FROM password WHERE id=" +id);
                //System.out.println("user id   "+ user_id+"   "+pass.getInt("user_id"));
                if(pass.next())
                if(! (pass.getInt("user_id")+"").equals(user_id))
                    return "not Auth";
                stmt.executeUpdate("DELETE FROM password WHERE id=" + id  );
                System.out.println("DELETE FROM password WHERE id=" + id );
            }catch (SQLException throwable) {
                throwable.printStackTrace();
            }
            return "password deleted successfully";
        }
        return "connection error";
    }
}