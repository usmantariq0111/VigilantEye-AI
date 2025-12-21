# # from test_model import predict_gif
# # import os

# # # Path to a sample GIF file
# # sample_gif_path = "static/uploads/7.gif"  # Update this if needed

# # # Check if the sample file exists
# # if not os.path.exists(sample_gif_path):
# #     print(f"❌ File not found: {sample_gif_path}")
# #     exit()

# # # Models to test
# # models = ["cnn", "resnet3d", "transformer"]

# # print("🧪 Testing models on:", sample_gif_path)
# # print("=" * 50)

# # for model_name in models:
# #     label, method = predict_gif(sample_gif_path, model_name)
# #     print(f"🧠 Model: {model_name.upper()}")
# #     print(f"   🔍 Prediction: {label.upper()}")
# #     print(f"   🧬 Infection Type: {method}")
# #     print("-" * 50)

# from test_model import predict_gif

# gif_path = "static/uploads/7.gif"  # Replace with your test file

# for model in ["resnet3d", "transformer"]:
#     label, method = predict_gif(gif_path, model)
#     print(f"🧠 Model: {model.upper()}")
#     print(f"   🔍 Prediction: {label.upper()}")
#     print(f"   🧬 Infection Type: {method}")
#     print("-" * 50)
