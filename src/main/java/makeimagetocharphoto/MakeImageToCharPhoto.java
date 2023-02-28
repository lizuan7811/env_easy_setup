package makeimagetocharphoto;

import java.awt.Color;
import java.awt.Graphics2D;
import java.awt.Image;
import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Objects;

import javax.imageio.ImageIO;

public class MakeImageToCharPhoto {

	public BufferedImage getBufferedImage(final String src) throws IOException {
		return ImageIO.read(Files.newInputStream(Paths.get(src.trim())));
	}

	public void write(BufferedImage image, BufferedWriter fop) {
		try {
			StringBuffer sb = new StringBuffer();
			for (int j = image.getMinY(); j < image.getHeight(); j++) {
				for (int i = image.getMinX(); i < image.getWidth(); i++) {
					RgbPixel pixel = getScreenPixel(image, i, j);
					int index = getChar(pixel);
					sb.append(DICTORY.charAt(index));
				}
				sb.append("\n");
			}
			fop.write(sb.toString());
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public BufferedImage zipImaggeFileWithRate(BufferedImage image, int width, int height) {
		if (Objects.isNull(image)) {
			return null;
		}
		if (width <= 0 && height <= 0) {
			return image;
		}
		int w = image.getWidth();
		int h = image.getHeight();
		double dbValue;
		if (width > 0 && height <= 0) {
			dbValue = width / (double) w;
			height = (int) (h * dbValue);
		} else if (height > 0 && width <= 0) {
			dbValue = height / (double) h;
			width = (int) (w * dbValue);
		}

		BufferedImage bfImage = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
		Graphics2D graphics = bfImage.createGraphics();
		graphics.getFontRenderContext();
		graphics.setBackground(new Color(255, 255, 255));
		graphics.setColor(new Color(255, 255, 255));
		graphics.fillRect(0, 0, width, height);
		graphics.drawImage(image.getScaledInstance(width, height, Image.SCALE_SMOOTH), 0, 0, null);
		System.out.printf("壓縮圖片(寬:%d,高:%d\n", width, height);
		return bfImage;
	}

	public BufferedImage getGrayBufferedImage(final BufferedImage image) {
		int width = image.getWidth();
		int height = image.getHeight();
		BufferedImage grayImage = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_GRAY);
		for (int i = 0; i < width; i++) {
			for (int j = 0; j < height; j++) {
				int rgb = image.getRGB(i, j);
				grayImage.setRGB(i, j, rgb);
			}
		}
		return grayImage;
	}

	public BufferedImage getBinaryBufferedImage(final BufferedImage image) {
		if (image == null) {
			return null;
		}
		int width = image.getWidth();
		int height = image.getHeight();
		BufferedImage binaryImage = new BufferedImage(width, height, BufferedImage.TYPE_BYTE_BINARY);
		for (int i = 0; i < width; i++) {
			for (int j = 0; j < height; j++) {
				int rgb = image.getRGB(i, j);
				binaryImage.setRGB(i, j, rgb);
			}
		}
		return binaryImage;
	}

	private RgbPixel getScreenPixel(BufferedImage image, int x, int y) {
		if (isLegal(image, x, y)) {
			RgbPixel rgb = new RgbPixel();
			int pix = image.getRGB(x, y);
			rgb.setRed((pix >> 16) & 0xff);
			rgb.setGreen((pix >> 8) & 0xff);
			rgb.setBlue(pix & 0xff);
			return rgb;
		}
		return null;
	}

	private boolean isLegal(BufferedImage image, int x, int y) {
		int width = image.getWidth();
		int height = image.getHeight();
		return (x >= 0 && x < width && y >= 0 && y < height);
	}

	private final String DICTORY = " .,'-`&:1234567890+*abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ~!@#$%^&*()[]{}";
	private final int DICTORY_LEN = DICTORY.length();
	private final int STEP =10;

	private int getChar(RgbPixel rgb) {
		double key =Math.round(rgb.getGray()*(DICTORY_LEN-1)/255);
//		double key = DICTORY_LEN - Math.round(rgb.getGray() / STEP);
		if (key >= 1) {
			key -= 1;
		}
		return (int) key;
	}

}

class RgbPixel {
	private int red;
	private int green;
	private int blue;

	public int getRed() {
		return red;
	}

	public void setRed(int red) {
		this.red = red;
	}

	public int getGreen() {
		return green;
	}

	public void setGreen(int green) {
		this.green = green;
	}

	public int getBlue() {
		return blue;
	}

	public void setBlue(int blue) {
		this.blue = blue;
	}

	public double getGray() {
		double gray = red * 0.299 + green * 0.587 + blue * 0.114;
		return gray;
	}
}