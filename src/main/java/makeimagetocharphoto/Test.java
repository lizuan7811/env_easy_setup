package makeimagetocharphoto;

import java.awt.image.BufferedImage;
import java.io.File;
import java.io.FileWriter;

import javax.imageio.ImageIO;

public class Test {
	final static String photoPath = "C:\\Users\\ASUS\\Desktop\\Snipaste_2023-02-28_11-23-28.png";
	final static String producePhotoPath = "C:\\Users\\ASUS\\Desktop\\phototext.txt";

	 public static void main(String[] args) throws Exception {
	        String filename =photoPath; // 要轉換的圖片文件名
	        int width = 200; // 字元圖的寬度
	        int height = 200; // 字元圖的高度
	        BufferedImage image = ImageIO.read(new File(filename)); // 讀取圖片
	        image = resize(image, width, height); // 調整圖片大小
	        String ascii = convertToAscii(image); // 轉換為字元圖
	        FileWriter writer = new FileWriter(producePhotoPath); // 創建輸出文件
	        writer.write(ascii); // 寫入字元圖
	        writer.close(); // 關閉文件
	    }

	    // 調整圖片大小
	    public static BufferedImage resize(BufferedImage image, int width, int height) {
	        BufferedImage resizedImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
	        resizedImage.createGraphics().drawImage(image, 0, 0, width, height, null);
	        return resizedImage;
	    }

	    // 將圖片轉換為字元圖
	    public static String convertToAscii(BufferedImage image) {
	        StringBuilder sb = new StringBuilder();
	        String asciiChars = "@#S%?*+;:,.";
	        for (int y = 0; y < image.getHeight(); y++) {
	            for (int x = 0; x < image.getWidth(); x++) {
	                int pixel = image.getRGB(x, y);
	                int r = (pixel >> 16) & 0xff;
	                int g = (pixel >> 8) & 0xff;
	                int b = pixel & 0xff;
	                float gray = 0.2126f * r + 0.7152f * g + 0.0722f * b;
	                int index = Math.round(gray * (asciiChars.length() - 1) / 255);
	                sb.append(asciiChars.charAt(index));
	            }
	            sb.append("\n");
	        }
	        return sb.toString();
	    }
}
