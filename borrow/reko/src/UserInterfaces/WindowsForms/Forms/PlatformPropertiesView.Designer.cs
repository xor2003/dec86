namespace Reko.UserInterfaces.WindowsForms.Forms
{
    partial class PlatformPropertiesView
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            label2 = new System.Windows.Forms.Label();
            label1 = new System.Windows.Forms.Label();
            ddlPlatforms = new System.Windows.Forms.ComboBox();
            SuspendLayout();
            // 
            // label2
            // 
            label2.Anchor =  System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left | System.Windows.Forms.AnchorStyles.Right;
            label2.BackColor = System.Drawing.Color.White;
            label2.Font = new System.Drawing.Font("Tahoma", 15.75F);
            label2.Location = new System.Drawing.Point(0, 34);
            label2.Margin = new System.Windows.Forms.Padding(7, 0, 7, 0);
            label2.Name = "label2";
            label2.Size = new System.Drawing.Size(1570, 70);
            label2.TabIndex = 10;
            label2.Text = "Platform";
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new System.Drawing.Point(20, 125);
            label1.Name = "label1";
            label1.Size = new System.Drawing.Size(193, 32);
            label1.TabIndex = 11;
            label1.Text = "Custom Platform";
            // 
            // ddlPlatforms
            // 
            ddlPlatforms.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            ddlPlatforms.FormattingEnabled = true;
            ddlPlatforms.Location = new System.Drawing.Point(26, 175);
            ddlPlatforms.Name = "ddlPlatforms";
            ddlPlatforms.Size = new System.Drawing.Size(371, 40);
            ddlPlatforms.TabIndex = 12;
            // 
            // PlatformPropertiesView
            // 
            AutoScaleDimensions = new System.Drawing.SizeF(13F, 32F);
            AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            Controls.Add(ddlPlatforms);
            Controls.Add(label1);
            Controls.Add(label2);
            Name = "PlatformPropertiesView";
            Size = new System.Drawing.Size(1570, 654);
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private System.Windows.Forms.Label label2;
        private System.Windows.Forms.Label label1;
        private System.Windows.Forms.ComboBox ddlPlatforms;
    }
}
