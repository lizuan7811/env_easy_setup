package env_easy_setup;

import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.BufferedWriter;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.Optional;

import keyproduce.KeyUtils;
import makeimagetocharphoto.MakeImageToCharPhoto;

public class TestMain {
	public static void main(String[] args) throws Exception {
		testPhotoTool();
	}

	private static void testPhotoTool() {
		final String photoPath = "D:\\D_BOX\\4PhotoS\\BigHead\\12153.jpg";
		final String producePhotoPath = "C:\\Users\\ASUS\\Desktop\\phototext.txt";
		MakeImageToCharPhoto makeImageToCharPhoto = new MakeImageToCharPhoto();
		try (BufferedWriter bos = Files.newBufferedWriter(Paths.get(producePhotoPath))) {
			BufferedImage bufferedImage = makeImageToCharPhoto.getBufferedImage(photoPath);
//			bufferedImage=makeImageToCharPhoto.getGrayBufferedImage(bufferedImage);
//			bufferedImage=makeImageToCharPhoto.getBinaryBufferedImage(bufferedImage);
			bufferedImage=makeImageToCharPhoto.zipImaggeFileWithRate(bufferedImage,800,150);
			makeImageToCharPhoto.write(bufferedImage, bos);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	private static void testKeyTool() {
		KeyUtils keyUtils = new KeyUtils("test", 4096, "RSA", 10);
		Path extFilePath = Paths
				.get("C:/Users/ASUS/eclipse-workspace/env_easy_setup/src/main/resources/shell_dir/v3.ext");
		System.out.println(keyUtils.issueCertificate(extFilePath));
	}

}
