public class Alfabeto {
    private char caracter;
    private int pos;

    Alfabeto(char c){
        this.caracter = c;
    }

    Alfabeto(char c, int pos){
        this.caracter = c;
        this.pos = pos;
    }

    ///GETTERS AND SETTERS///
    public char getChar(){ return this.caracter; }
    public int getPos(){ return this.pos; }


}
