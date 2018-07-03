import java.io.Serializable;

public class Message implements Serializable {

    private String text;
    private String sign;

    public Message(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

    public void setText(String text) {
        this.text = text;
    }

    public String getSign() {
        return sign;
    }

    public void setSign(String sign) {
        this.sign = sign;
    }

    public String toString(){
        return text;
    }
}
